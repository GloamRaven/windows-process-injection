#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int main() {
	WCHAR procName[260];
	wprintf(L"Enter process name: ");
	wscanf_s(L"%259ls", procName, (unsigned)_countof(procName));

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	BOOL bFound = FALSE;
	if (Process32FirstW(hSnap, &pe)) {
		do {
			if (wcscmp(procName, pe.szExeFile) == 0) {
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
				if (hProc == NULL) {
					wprintf(L"OpenProcess failed. Error: %d\n", GetLastError());
				}
				else {
					wprintf(L"%ls(%d) Handle: %p\n", pe.szExeFile, pe.th32ProcessID, hProc);
					CloseHandle(hProc);
				}
				bFound = TRUE;
				break;
			}
		} while (Process32NextW(hSnap, &pe));
	}
	if (!bFound) wprintf(L"Process not found.\n");

	CloseHandle(hSnap);
	return 0;
}