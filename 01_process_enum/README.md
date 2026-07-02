## What this does
Lists all running processes on the system.

## APIs Used
- `CreateToolhelp32Snapshot` - Takes a snapshot of running processes
- `Process32First` / `Process32Next` - Retrieves information about processes in the snapshot

## Why it works
CreateToolhelp32Snapshot captures a snapshot of running processes at the moment it is called.
Process32First and Process32Next iterate through the snapshot.
Each iteration fills a PROCESSENTRY32 struct with information about one process.