## What this does
Finds a specific process by PID.

## APIs Used
- `CreateToolhelp32Snapshot` - Takes a snapshot of running processes
- `Process32FirstW` / `Process32NextW` - Iterates through the snapshot and retrieves process information

## Why it works
CreateToolhelp32Snapshot captures a snapshot of running processes at the moment it is called.
Process32First and Process32Next iterate through the snapshot and fills a PROCESSENTRY32 struct with process information.
The struct contains the PID (th32ProcessID), which is compared against the target PID to find a match.