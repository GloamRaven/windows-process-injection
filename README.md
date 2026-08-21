# Windows Process Injection
Implementations of Windows process injection techniques in C, each with a write-up covering how it works and how defenders detect it.

| # | Technique | MITRE | Status |
|---|-----------|-------|----------|
| 01 | [Classic DLL Injection](01-dll-injection/) | T1055.001 | ✅ [Blog](https://gloamraven.github.io/posts/dllinjection/) |
| 02 | [Shellcode Injection](02-shellcode-injection/) | T1055 | ✅ [Blog](https://gloamraven.github.io/posts/shellcodeinjection/) |
| 03 | APC Injection | T1055.004 | 🚧 |

Built and tested on Windows 10 x64.

## Purpose & Scope
This repository is written for security research and education. All code is run against processes on machines I control, inside an isolated VM. Do not use these techniques against systems you do not own or have explicit permission to test.

Every technique here is publicly documented and mapped to MITRE ATT&CK. The code is intentionally minimal and non-evasive. The injected code performs no malicious action; it only displays a message box to prove execution. The goal is to understand why each technique works and what artifacts it leaves behind for defenders.

## License
MIT - see [LICENSE](LICENSE).
