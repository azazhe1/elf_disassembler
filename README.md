# elf_disassembler
Disassemble x86-64 ELF files


# Source 
[Linear Sweep x86 Disassembler](https://techryptic.github.io/2017/09/25/Linear-sweep-x86-Disassembler/)

[X86-64 Instruction Encoding](https://wiki.osdev.org/X86-64_Instruction_Encoding)

[Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm#disassembly)

[X86 Opcode and Instruction Reference](http://ref.x86asm.net/coder64.html)


# Exemple :

0:  48 35 78 56 34 12       xor    rax,0x12345678
6:  29 c0                   sub    eax,eax


0:  48 35 34 12 00 00       xor    rax,0x1234
6:  29 c0                   sub    eax,eax



# TODO
+ Ajout le support de 3 opérande
+ Ajout instruction IMUL
+ Ajout Legacy Prefix
+ Ajout REX