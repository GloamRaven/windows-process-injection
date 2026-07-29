# Classic DLL Injection
`LoadLibrary` + `CreateRemoteThread` - the most fundamental process injection technique on Windows. It forces a target process to load a DLL from disk by running `LoadLibrary` inside that process via a remote thread.

**MITRE ATT&CK:** [T1055.001 - Dynamic-link Library Injection(https://attack.mitre.org/techniques/T1055/001/)]

## How it works
1. **Open** a handle to the target process - `OpenProcess`
2. **Allocate** memory inside the target - `VirtualAllocEx`
3. **Write** the DLL path into that memory - `WriteProcessMemory`
4. **Resolve** the address of `LoadLibraryW` in `kernel32.dll` - `GetProcAddress`
5. **Execute** it in the target with the DLL path as its argument - `CreateRemoteThread`

`kernel32.dll` is mapped at the same address across processes in a session, so the `LoadLibraryW` address resolved locally is valid in the target - that's why step 4 works.

## Build & run
Opens a *Developer Command Prompt for Visual Studio*, then build both parts:

```console
cl /LD payload.c
cl injector.c
```

Run the injector. It prompts for the name of the target process and the absolute path of the DLL to inject:

```console
> injector.exe
Enter process name: notepad.exe
Enter DLL path: C:\lab\payload.dll
Success find notepad.exe(7592)
Success open process
Success Memory Allocate: 0000015D68230000
Success write dll path in memory
Success get LoadLibraryW address
Success DLL injection
```

## Detection & defense
This technique is easy to detect, because every step is visible to the OS:
- A `CreateRemoteThread` call whose start address is `LoadLibraryA` or `LoadLibraryW`
- `VirtualAllocEx` used on another process. My injector only needs `PAGE_READWRITE` here, because the bytes I write are just a DLL path, not code to execute
- The target process suddenly loads a DLL from an unusual folder, which security tools can see as a module-load event

**Limitation:** `LoadLibrary` only takes a file path, so the DLL has to be written to disk first. That gives antivirus a file to scan and leaves an obvious artifact behind. Shellcode injection avoids this by writing the code itself into memory instead.

## Write-up
Full walkthrough with internals and screenshots:
