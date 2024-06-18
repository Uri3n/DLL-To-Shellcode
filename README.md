# DLL-To-Shellcode
This tool converts a Windows DLL to position-independent code (shellcode) by prepending the DLL with a stub that loads the DLL.

## Why does this exist
  1. I needed a simple conversion tool for an agent I'm working on and found Donut too complex.
  2. Some other shellcode conversion tools require the shellcode to be loaded into a read/write/execute buffer,
     a restriction I did not want. This loader generates shellcode that can be used in a R/X context.

 ## Restrictions
 This loader is extremely simple and basic. It loads a Windows 64-bit DLL specifically. It does not support:
 - Executable PE files (ending in .exe)
 - .NET assemblies
 - 32 bit DLLs

## Should you use this?
Probably not. I created this tool because I needed something specific and simple for what I was working on.
I cannot guarantee, by any stretch, that this loader is stable or that it will not crash your implant. 
