#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#define MAX_PROCESS_NAME 260
#define MAX_DLL_PATH 260

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
			if (wcscmp(procName, pe.szExeFile) == 0) {
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
	WCHAR dllPath[MAX_DLL_PATH];
	HANDLE hProc	= NULL;
	LPVOID pMem		= NULL;
	HANDLE hThread	= NULL;
	int rc = 1;

	wprintf(L"Enter process name: ");
	if (!fgetws(procName, _countof(procName), stdin)) return 1;
	procName[wcscspn(procName, L"\r\n")] = L'\0';

	wprintf(L"Enter DLL path: ");
	if (!fgetws(dllPath, _countof(dllPath), stdin)) return 1;
	dllPath[wcscspn(dllPath, L"\r\n")] = L'\0';
	if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
		wprintf(L"DLL file not found\n");
		return 1;
	}

	DWORD pid = FindProcessId(procName);
	if (pid == 0) {
		wprintf(L"Process not found.\n");
		return 1;
	}
	
	wprintf(L"[+] Found %ls(PID %lu)\n", procName, pid);

	hProc = OpenProcess(
		PROCESS_CREATE_THREAD |		// CreateRemoteThread
		PROCESS_VM_OPERATION |		// VirtualAllocEx
		PROCESS_VM_WRITE,			// WriteProcessMemory
		FALSE, pid);
	if (hProc == NULL) {
		wprintf(L"OpenProcess failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}

	SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
	pMem = VirtualAllocEx(hProc, NULL, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pMem == NULL) {
		wprintf(L"VirtualAllocEx failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Allocated %zu bytes at %p\n", pathSize, pMem);

	if (!WriteProcessMemory(hProc, pMem, dllPath, pathSize, NULL)) {
		wprintf(L"WriteProcessMemory failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Wrote the DLL path into the target\n");

	FARPROC pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		wprintf(L"GetProcAddress failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] LoadLibraryW at %p\n", (void *)pLoadLibraryW);

	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pMem, 0, NULL);
	if (hThread == NULL) {
		wprintf(L"CreateRemoteThread failed. Error: %lu\n", GetLastError());
		goto cleanup;
	}
	wprintf(L"[+] Remote thread created\n");

	WaitForSingleObject(hThread, INFINITE);

	// The remote thread's exit code is LoadLibraryW's return value (HMODULE),
	// truncated to 32 bits. Non-zero means the DLL was loaded.
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	if (exitCode == 0) {
		wprintf(L"LoadLibraryW failed inside the target process\n");
		goto cleanup;
	}
	wprintf(L"[+] DLL loaded successfully\n");
	rc = 0;

cleanup:
	if (hThread)	CloseHandle(hThread);
	if (pMem)		VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
	if (hProc)		CloseHandle(hProc);
	return rc;
}