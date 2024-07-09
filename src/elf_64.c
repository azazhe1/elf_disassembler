#include "elf_64.h"
#include <stdio.h>
#include <stdlib.h>

#define SUPPORTED_ARCHI_COUNT (int)(sizeof(SUPPORTED_ARCHI) / sizeof(SUPPORTED_ARCHI[0]))

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
    printf("Prgram Entry point : 0x%016lx\n",elf_enry);
}

char *get_flags(uint32_t p_flags){
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

void parse_elf_header(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Phdr *phdr= (Elf64_Phdr*)&mem[ehdr->e_phoff];
    printf("Programe header :\n");
    for(int i=0; i<ehdr->e_phnum; i++){
        switch (phdr[i].p_type) {
            case PT_LOAD:
                printf("\tLOAD  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_DYNAMIC:
                printf("\tDYNAMIC  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_INTERP:
                printf("\tINTERP  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_NOTE:
                printf("\tNOTE  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_SHLIB:
                printf("\tSHLIB  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_PHDR:
                printf("\tPHDR  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_GNU_STACK:
                printf("\tSTACK  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_GNU_EH_FRAME:
                printf("\tEH_FRAME  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            case PT_GNU_RELRO:
                printf("\tRELRO  flags %s off 0x%016lx\n", get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
            default:
                printf("\t0x%x  flags %s off 0x%016lx\n", phdr[i].p_type, get_flags(phdr[i].p_flags), phdr[i].p_offset);
                break;
        }
    }
}

int elf_64_disass(char *filename, u_int8_t* mem){
    Elf64_Ehdr *ehdr;
    int elf_type,elf_archi;
    ehdr = (Elf64_Ehdr *)mem;
    elf_type = get_elf_type(filename, ehdr);
    if(elf_type == 0) goto end;
    elf_archi = get_architecture(filename, ehdr);
    if(elf_archi == 0) goto end;
    print_format(filename,elf_type,elf_archi,ehdr->e_entry);
    if(elf_archi != EM_X86_64){
        fprintf(stderr,"%s : Architecture not implemented\n",filename);
        goto end;
    }
    parse_elf_header(mem,ehdr);

end :
    return 0;
}