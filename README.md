# OS-9 Ghidra module

Ghidra extension to load and analyse Microware OS-9 for Motorola 68000 CPUs.

## Ghidra version

This extension requires Ghidra 11.4 or a later version.

To use it on previous versions of ghidra, open `ModuleHeader.java` and replace every occurence of `CommentType.EOL` (introduced in 11.4)  to `CodeUnit.EOL_COMMENT`, and import `ghidra.program.model.listing.CodeUnit`.

## Special thanks

- Phlosioneer (https://github.com/Phlosioneer) for his original source code that helped me getting started fast.

## TODO

- Add all possible OS-9 and CD-I data structures
    - Missing kernel data structures and CD-I ones.
- Add all system calls
    - Handle the OS-9 return value.
    - Add all their parameters.
- Add support for module groups (ideally load all of them at the same time).
- Add program exec input registers.
- Add calling conventions to standard functions
- Set parameters of standard routines.
