#include "elf_64.h"
#include <stdio.h>
#include <stdlib.h>

uint16_t SUPPORTED_ARCHI []= {EM_X86_64,EM_AARCH64,EM_MIPS,EM_RISCV};

uint16_t get_elf_type(char *filename, Elf64_Ehdr *ehdr){
    if (ehdr->e_type == ET_NONE){
        fprintf(stderr,"%s : Unknown type\n",filename);
        return 0;
    }else if(ehdr->e_type !=ET_EXEC && ehdr->e_type != ET_DYN){
        fprintf(stderr,"%s : It's not an executable or a shared object\n",filename);
        return 0;
    }
    return ehdr->e_type;
}

uint16_t get_architecture(char *filename, Elf64_Ehdr *ehdr){
    for(int i=0; i< SUPPORTED_ARCHI_COUNT; i++){
        if(ehdr->e_machine == SUPPORTED_ARCHI[i]) return ehdr->e_machine;
    }
    if(ehdr->e_machine == EM_NONE){
        fprintf(stderr,"%s : Unknown architecture\n",filename);
    }else{
        fprintf(stderr,"%s : Architecture not supported\n",filename);
    }
    return 0;
}

void print_format(char * filename, u_int8_t elf_type, u_int8_t elf_archi, Elf64_Addr elf_enry){
    char *type_str;
    char *archi_str;
    switch (elf_type)
    {
    case ET_EXEC:
        type_str =  "ET_EXEC";
        break;
    case ET_DYN:
        type_str =  "ET_DYN";
    default:
        break;
    }
    switch (elf_archi)
    {
    case EM_X86_64:
        archi_str =  "x86-64";
        break;
    case EM_AARCH64:
        archi_str =  "AArch64";
        break;
    case EM_MIPS:
        archi_str =  "MIPS";
        break;
    case EM_RISCV:
        archi_str =  "RISC-V";
        break;
    default:
        break;
    }
    printf("%s: ELF\t%s \tArchitecture: 64 bits, %s\n", filename, type_str, archi_str);
    printf("\nPrgram Entry point : 0x%016lx\n",elf_enry);
}

char *get_ph_flags(uint32_t p_flags){
    static char flags_str[4];
    memset(flags_str, '-', sizeof(flags_str) - 1);
    flags_str[3] = '\0';

    if (p_flags & PF_R)
        flags_str[0] = 'r';
    if (p_flags & PF_W)
        flags_str[1] = 'w';
    if (p_flags & PF_X)
        flags_str[2] = 'x';
    return flags_str;
}

int get_power_2(uint64_t p_align){
    return (int)(log(p_align)/log(2));
}

void get_program_header(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Phdr *phdr= (Elf64_Phdr*)&mem[ehdr->e_phoff];
    printf("\nProgram header :\n");
    printf("\t%-18s %-6s      %-16s %-16s %-16s\n", "", "FLAGS", "OFFSET", "VADDR", "PADDR");
    for(int i=0; i < ehdr->e_phnum; i++){
        switch (phdr[i].p_type) {
            case PT_LOAD:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "LOAD", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_DYNAMIC:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "DYNAMIC", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_INTERP:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "INTERP", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_NOTE:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "NOTE", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_SHLIB:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "SHLIB", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_PHDR:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "PHDR", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_STACK:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "GNU_STACK", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_EH_FRAME:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "EH_FRAME", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_RELRO:
                printf("\t%-18s %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", "RELRO", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            default:
                printf("\t0x%016x %-6s %016lx %016lx %016lx\n\tfilesz 0x%016lx memsz 0x%016lx align 2^%d\n", phdr[i].p_type, get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
        }
    }
}

Elf64_Shdr get_section_header(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Shdr *shdr= (Elf64_Shdr*)&mem[ehdr->e_shoff];
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];//Find the section header string table
    Elf64_Shdr sym_shdr;
    const char *shstrtab_p = (const char*)&mem[shstrtab->sh_offset];
    printf("\nSection header :\n");
    printf("\t%-20s   %-8s      %-14s %-11s %-5s %-3s\n", "", "SIZE", "VMA", "OFFSET", "FLAGS", "ALIGN");
    for(int i = 0; i < ehdr->e_shnum; i++) {
        if(shstrtab_p[shdr[i].sh_name] != '\0') {
            if(shdr[i].sh_type == SHT_SYMTAB) sym_shdr = shdr[i];
            printf("\t%-20s %08lx %016lx %016lx %05lx 2^%d\n", &shstrtab_p[shdr[i].sh_name], shdr[i].sh_size, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_flags, get_power_2(shdr[i].sh_addralign));
        }
    }
    return sym_shdr;
}

void get_sym_table(u_int8_t* mem, Elf64_Shdr sym_shdr,  Elf64_Ehdr *ehdr){
    Elf64_Sym *sym = (Elf64_Sym *)&mem[sym_shdr.sh_offset];
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)&mem[ehdr->e_shoff];//find the section symbole string table
    Elf64_Shdr *strtab_shdr = &shdr_table[sym_shdr.sh_link];
    char *strtab = (char *)&mem[strtab_shdr->sh_offset];
    int table_size =  TABLE_SIZE(sym_shdr);
    printf("\nSymoble table :\n");
    printf("\t%-16s %-16s %s\n", "Value", "Size", "Name");

    for(int i = 0; i < table_size; i++){
        if(sym[i].st_name != 0) printf("\t%016lx %016lx %s\n", sym[i].st_value, sym[i].st_size ,strtab + sym[i].st_name);
    }
}

int elf_64_disass(char *filename, u_int8_t* mem){
    Elf64_Ehdr *ehdr;
    Elf64_Shdr sym_shdr;
    int elf_type,elf_archi;
    ehdr = (Elf64_Ehdr *)mem;
    elf_type = get_elf_type(filename, ehdr);
    if(elf_type == 0) goto end;
    elf_archi = get_architecture(filename, ehdr);
    if(elf_archi == 0) goto end;
    print_format(filename, elf_type, elf_archi, ehdr->e_entry);
    if(elf_archi != EM_X86_64){
        fprintf(stderr, "%s : Architecture not implemented\n", filename);
        goto end;
    }
    get_program_header(mem, ehdr);
    sym_shdr = get_section_header(mem, ehdr);
    get_sym_table(mem, sym_shdr, ehdr);

end :
    return 0;
}