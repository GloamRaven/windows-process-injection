#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
	if (argc != 2) {
		wprintf(L"usage: find_process.exe {pid}");
		return 0;
	}
	DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	BOOL bFound = FALSE;
	if (Process32FirstW(hSnap, &pe)) {
		do {
			if (pid == pe.th32ProcessID) {
				wprintf(L"Pid %d: %ls\n", pe.th32ProcessID, pe.szExeFile);
				bFound = TRUE;
				break;
			}
		} while (Process32NextW(hSnap, &pe));
	}
	if (!bFound) wprintf(L"Process not found.\n");

	CloseHandle(hSnap);
	return 0;
}