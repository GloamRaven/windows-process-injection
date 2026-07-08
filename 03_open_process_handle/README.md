## What this does
Finds a specific process by name and opens a handle to it.

## APIs Used
- `CreateToolhelp32Snapshot` - Takes a snapshot of running processes
- `Process32FirstW` / `Process32NextW` - Iterates through the snapshot and retrieves process information
- `OpenProcess` - Opens a process handle by PID

## Why it works
A snapshot includes process information such as PID and process name in a PROCESSENTRY32W struct.
When a process name is entered, takes a snapshot and finds the struct by matching the process name.
Finally, opens a process handle using the PID in the struct.