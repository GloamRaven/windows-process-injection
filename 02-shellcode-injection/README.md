# Shellcode Injection
`VirtualProtectEx` + `CreateRemoteThread` - inject position-independent code into a remote process and run it there. Unlike DLL injection, nothing is writtten to disk and the payload is not limited to a single argument.

**MITRE ATT&CK:** [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)

## How it works
1. **Open** a handle to the target process - `OpenProcess`
2. **Allocate** writable memory inside the target - `VirtualAllocEx` (`PAGE_READWRITE`)
3. **Write** the shellcode into that memory - `WriteProcessMemory`
4. **Flip** the page to executable - `VirtualProtectEx` (`PAGE_EXECUTE_READ`)
5. **Execute** it - `CreateRemoteThread`

The page is never writable and executable at the same time. A single `PAGE_EXECUTE_READWRITE` allocation is shorter, but RWX private memory is one of the loudest signals an EDR can look for.

Once running, the shellcode has no imports to rely on, so it resolves everything itself:

1. Walk the PEB to find the base address of `kernel32.dll`
2. Parse its export directory and locate `LoadLibraryA` by name hash
3. Load `user32.dll`, which is not guaranteed to be mapped in the target
4. Repeat the export walk on `user32.dll` to locate `MessageBoxA`
5. Build the argument strings on the stack and call it

API names are matched by hash rather than by string comparison. A hash is a single constant no matter how long the name is, while assembling a name on the stack costs one instruction per character, and no readable API name ends up in the payload either.

## Build & run
Open an *x64 Native Tools Command Prompt* (any Visual Studio version). The shellcode is assembled first, then extracted into a C header that the injector includes:

```console
ml64 /c /Fo shell.obj sc.asm
cl extractor.c shell.obj
extractor.exe > shellcode.h
cl injector.c
```
`sc.asm` is the source of truth. `shellcode.h` is generated - do not edit it by hand.

Run the injector. It prompts for the name of the target process:

```console
> injector.exe
Enter process name: Notepad.exe
[+] Found Notepad.exe(PID 5676)
[+] Allocated 503 bytes at 000002371F070000
[+] Wrote the shellcode into the target
[+] Changed the memory protection to PAGE_EXECUTE_READ
[+] Remote thread created
[+] Shellcode executed successfully
```
The last line is not just a message. The shellcode leaves a non-zero value in `rax` on success and zero on any failure, and that value becomes the remote thread's exit code, so the injector can confirm the payload actually ran instead of only confirming that a thread started.

## Detection & defense
Some of the signals from DLL injection are gone, and new one appears:
- **No module-load event.** Nothing is loaded from disk, so the target never reports a new DLL. The clearest artifact from the previous technique is missing here
- **A `CreateRemoteThread` whose start address is private memory.** In DLL injection the start address was LoadLibraryW inside kernel32.dll. Here it points into a region that is not backed by any file on disk, which is harder to explain away than the previous case
- **A remote process gets executable private memory.** The `VirtualAllocEx` / `VirtualProtectEx` pair on another process is visible regardless of the order the permissions are applied in

## Limitations
- **The name hash is a plain byte sum.** Any two names built from the same letters collide, and the loop takes the first match in an alphabetically sorted table, so a colliding export that sorts earlier would resolve to the wrong function. A rotating hash such as ROR-13 makes this practically impossible
- **The module walk assumes a load order.** The shellcode takes the third entry of `InLoadOrderModuleList` as `kernel32.dll`. That holds in practice but is not documented behaviour
- **The thread still starts at the payload.** `CreateRemoteThread` remains the most direct thing to alert on, and the start address points straight at the injected region

APC injection removes the last one: instead of creating a thread that begins at the payload, it queues the payload onto a thread the target already owns. See the write-up for the full reasoning.

## Write-up
Full walkthrough with internals and screenshots: [https://gloamraven.github.io/posts/dllinjection/](https://gloamraven.github.io/posts/shellcodeinjection/)
