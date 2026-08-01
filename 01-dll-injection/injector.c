#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#define MAX_PROCESS_NAME 260
#define MAX_DLL_PATH 260

int main() {
	WCHAR procName[MAX_PROCESS_NAME];
	wprintf(L"Enter process name: ");
	if (!fgetws(procName, _countof(procName), stdin)) return 1;
	procName[wcscspn(procName, L"\r\n")] = L"\0";

	WCHAR dllPath[MAX_DLL_PATH];
	wprintf(L"Enter DLL path: ");
	if (!fgetws(dllPath, _countof(dllPath), stdin)) return 1;
	dllPath[wcscspn(dllPath, L"\r\n")] = L"\0";
	if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
		wprintf(L"DLL file not found\n");
		return 1;
	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	BOOL bFound = FALSE;
	HANDLE hProc;
	LPVOID pMem;
	HANDLE hThread;
	if (Process32FirstW(hSnap, &pe)) {
		do {
			if (wcscmp(procName, pe.szExeFile) == 0) {
				wprintf(L"Success find %ls(%lu)\n", procName, pe.th32ProcessID);
				hProc = OpenProcess(
					PROCESS_CREATE_THREAD |		// CreateRemoteThread
					PROCESS_VM_OPERATION |		// VirtualAllocEx
					PROCESS_VM_WRITE,			// WriteProcessMemory
					FALSE, pe.th32ProcessID);
				if (hProc == NULL) {
					wprintf(L"OpenProcess failed. Error: %lu\n", GetLastError());
				}
				else {
					wprintf(L"Success open process\n");
					SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
					pMem = VirtualAllocEx(hProc, NULL, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
					if (pMem == NULL) {
						wprintf(L"VirtualAllocEx failed. Error: %lu\n", GetLastError());
					}
					else {
						wprintf(L"Success Memory Allocate: %p\n", pMem);
						if (!WriteProcessMemory(hProc, pMem, dllPath, pathSize, NULL)) {
							wprintf(L"WriteProcessMemory failed. Error: %lu\n", GetLastError());
							goto cleanup;
						}
						wprintf(L"Success write dll path in memory\n");

						FARPROC pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
						if (pLoadLibraryW == NULL) {
							wprintf(L"GetProcAddress failed. Error: %lu\n", GetLastError());
							goto cleanup;
						}
						wprintf(L"Success get LoadLibraryW address\n");

						hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pMem, 0, NULL);
						if (hThread == NULL) {
							wprintf(L"CreateRemoteThread failed. Error: %lu\n", GetLastError());
							goto cleanup;
						}
						wprintf(L"Success DLL injection\n");
						WaitForSingleObject(hThread, INFINITE);
						goto cleanup;
					}
				}
				bFound = TRUE;
				break;
			}
		} while (Process32NextW(hSnap, &pe));
	}
	if (!bFound) wprintf(L"Process not found.\n");
cleanup:
	if (hThread) CloseHandle(hThread);
	if (pMem) VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
	if (hProc) CloseHandle(hProc);
	if (hSnap != INVALID_HANDLE_VALUE) CloseHandle(hSnap);
	return 0;
}