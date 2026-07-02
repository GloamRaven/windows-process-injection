#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int main() {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	int i = 1;
	if (Process32First(hSnap, &pe)) {
		do {
			wprintf(L"%d\tpid: %d\tppid: %d\tthreads: %d\t%ls\n", i, pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads, pe.szExeFile);
			i++;
		} while (Process32Next(hSnap, &pe));
	}

	CloseHandle(hSnap);
	return 0;
}