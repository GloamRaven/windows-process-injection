## What this does
Finds a specific process by name and allocates memory in the process.

## APIs Used
- `CreateToolhelp32Snapshot` - Takes a snapshot of running processes
- `Process32FirstW` / `Process32NextW` - Iterates through the snapshot and retrieves process information
- `OpenProcess` - Opens a process handle by PID
- `VirtualAllocEx` - Allocates memory in another process

## Why it works
A snapshot includes process information such as PID and process name in a PROCESSENTRY32W struct.
When a process name is entered, takes a snapshot and finds the struct by matching the process name.
Then opens a process handle with PROCESS_VM_OPERATION access right, which is required to use VirtualAllocEx API.
VirtualAllocEx allocates a 4096-byte (one page) region in the target process's virtual address space and returns its address.