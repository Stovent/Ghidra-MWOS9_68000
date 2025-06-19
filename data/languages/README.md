# 68000_OS9

This is a modifiation of Ghidra's 68000 processor to support Microware OS-9's system call syntax.
For various reasons every system call is declared in this specification instead of relying on Java analysis.

## Specifics
- `68000_OS9.sinc` have been modified to remove the trap decoding and instead include `OS9_trap.sinc`
- `OS9_traps.sinc` defines the necessary tokens and instructions for OS-9 and include `OS9_syscalls.sinc`
- `OS9_syscalls.sinc` is a generated file that defines every system call for disassembly and analysis, including input, output and error registers.

`OS9_syscalls.sinc` is generated from the script located at `ghidra_scripts/generate_os9_syscall_sleigh.py`.
The input JSON data is located in `data/os9_system_calls.json` and contains a descriptions of each system call:
- "id": the system call number.
- "name": the display name of the system call (the '$' is removed by the script because Ghidra doesn't support it for identifiers).
- "input": The list of input registers.
- "output": The list of outputs on success, as a dictionnary of the name of the return value as the key and the register it is in as the value.
- "noerror": Optional. If present, indicates that the system call cannot return an error and thus doesn't have to check the carry flag.
- "noreturn": Optional. If present, indicates that the system call never returns to the caller. Ideally Ghidra should stop reading instructions after this.
