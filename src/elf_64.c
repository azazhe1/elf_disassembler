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
    case ET_EXEC:   type_str =  "ET_EXEC"; break;
    case ET_DYN:    type_str =  "ET_DYN"; break;
    default:        type_str = "Unknow"; break;
    }
    switch (elf_archi)
    {
    case EM_X86_64:     archi_str =  "x86-64"; break;
    case EM_AARCH64:    archi_str =  "AArch64"; break;
    case EM_MIPS:       archi_str =  "MIPS"; break;
    case EM_RISCV:      archi_str =  "RISC-V"; break;
    default:            archi_str = "Unknow"; break;
    }
    printf("%s:\tArchitecture: 64 bits, %s, %s\n", filename, archi_str, type_str);
    printf("Prgram Entry point: 0x%016lx\n",elf_enry);
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
    printf(" %-18s %-6s      %-16s %-16s %-16s\n", "", "FLAGS", "OFFSET", "VADDR", "PADDR");
    for(int i=0; i < ehdr->e_phnum; i++){
        switch (phdr[i].p_type) {
            case PT_LOAD:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "LOAD", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_DYNAMIC:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "DYNAMIC", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_INTERP:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "INTERP", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_NOTE:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "NOTE", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_SHLIB:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "SHLIB", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_PHDR:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "PHDR", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_STACK:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "GNU_STACK", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_EH_FRAME:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "EH_FRAME", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            case PT_GNU_RELRO:
                printf(" %-18s %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", "RELRO", get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
            default:
                printf(" 0x%016x %-6s %016lx %016lx %016lx\n filesz 0x%016lx memsz 0x%016lx align 2^%d\n", phdr[i].p_type, get_ph_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, get_power_2(phdr[i].p_align));
                break;
        }
    }
}

void get_section_header(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Shdr *shdr= (Elf64_Shdr*)&mem[ehdr->e_shoff];
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];//Find the section header string table
    const char *shstrtab_p = (const char*)&mem[shstrtab->sh_offset];

    printf("\nSection header :\n");
    printf(" %-20s   %-8s      %-14s %-11s %-5s %-3s\n", "", "SIZE", "VMA", "OFFSET", "FLAGS", "ALIGN");
    for(int i = 0; i < ehdr->e_shnum; i++) {
        if(shstrtab_p[shdr[i].sh_name] != '\0') {
            printf(" %-20s %08lx %016lx %016lx %05lx 2^%d\n", &shstrtab_p[shdr[i].sh_name], shdr[i].sh_size, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_flags, get_power_2(shdr[i].sh_addralign));
        }
    }
}

int  get_section(u_int8_t* mem, Elf64_Ehdr *ehdr, uint32_t value, Elf64_Shdr *result){
    Elf64_Shdr *shdr= (Elf64_Shdr*)&mem[ehdr->e_shoff];

    for(int i=0; i < ehdr->e_shnum; i++){
        if(shdr[i].sh_type == value){
            *result = shdr[i];
            return 0;
        }
    }
    return 1;
}

int get_group_section(u_int8_t* mem, Elf64_Ehdr *ehdr, uint32_t value, Elf64_Shdr **result){
    Elf64_Shdr *shdr= (Elf64_Shdr*)&mem[ehdr->e_shoff];
    Elf64_Shdr *res;
    int count = 0;
    int index = 0;
    for(int i = 0; i < ehdr->e_shnum; i++){
        if(shdr[i].sh_type == value){
            count++;
        }
    }
    if(count == 0){
        return 0;
    }
    res = (Elf64_Shdr *)malloc(count * sizeof(Elf64_Shdr));
    if (res == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    for(int i = 0; i < ehdr->e_shnum; i++){
         if(shdr[i].sh_type == value){
            res[index] = shdr[i];
            index++; 
        }
    }
    *result = res;
    return count;
}

char *get_symbole_type(unsigned char st_info){
    char *type;

    switch (ELF64_ST_TYPE(st_info))
    {
    case STT_NOTYPE:    type = "NOTYPE"; break;
    case STT_OBJECT:    type = "OBJECT"; break;
    case STT_FUNC:      type = "FUNC"; break;
    case STT_SECTION:   type = "SECTION"; break;
    case STT_FILE:      type = "FILE"; break;
    case STT_COMMON:    type = "COMMON"; break;
    case STT_TLS:       type = "TLS"; break;; 
    default:            type = "UNKNOWN"; break;
    }
    return type;
}

char *get_symbol_bind(unsigned char st_info){
    char *bind;

    switch (ELF64_ST_BIND(st_info)) {
        case STB_LOCAL:  bind = "LOCAL"; break;
        case STB_GLOBAL: bind = "GLOBAL"; break;
        case STB_WEAK:   bind = "WEAK"; break;
        default:         bind = "UNKNOWN"; break;
    }
    return bind;
}

char *get_symbol_visibility(unsigned char st_other){
    char *visibility;

    switch (ELF64_ST_VISIBILITY(st_other)) {
        case STV_DEFAULT:       visibility = "DEFAULT"; break;
        case STV_INTERNAL:      visibility = "INTERNAL"; break;
        case STV_HIDDEN:        visibility = "HIDDEN"; break;
        case STV_PROTECTED:     visibility = "PROTECTED"; break;
        default:                visibility = "UNKNOWN"; break;
    }    
    return visibility;
}

Symbol64_Info *get_table(u_int8_t* mem, Elf64_Ehdr *ehdr, Elf64_Shdr syms_shdr){
    Elf64_Sym *sym = (Elf64_Sym *)&mem[syms_shdr.sh_offset];
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)&mem[ehdr->e_shoff];//find the section symbole string table
    Elf64_Shdr *strtab_shdr = &shdr_table[syms_shdr.sh_link];
    char *strtab = (char *)&mem[strtab_shdr->sh_offset];
    int table_size = TABLE_SIZE(syms_shdr);
    Symbol64_Info *res = malloc(table_size * sizeof(Symbol64_Info));

    if (res == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    for(int i=0 ; i < table_size; i++){
        if(sym[i].st_name!=0){
            res[i].st_value = sym[i].st_value;
            res[i].st_size = sym[i].st_size;
            res[i].st_info =  sym[i].st_info;
            res[i].st_other =  sym[i].st_other;
            res[i].st_name = strtab + sym[i].st_name;
        }else{
            res[i].st_value = 0;
            res[i].st_size = 0;
            res[i].st_info =  0;
            res[i].st_other =  0;
            res[i].st_name = 0;
            res[i].table_size = table_size;
        }
    }
    return res;
}

Symbol64_Info *get_symbol(u_int8_t* mem, Elf64_Ehdr *ehdr, int show){
    Elf64_Shdr syms_shdr;
    Symbol64_Info *syms;

    printf("\nSymbol table :\n");
    if(get_section(mem, ehdr, SHT_SYMTAB, &syms_shdr)){
        fprintf(stderr," No symbol found\n");
        return NULL;
    }
    syms = get_table(mem, ehdr, syms_shdr);
    if(show){
        printf("      %-16s  %-10s %-7s %-7s %-9s %s\n", "VALUE", "SIZE", "TYPE", "BIND", "VISI", "NAME");
        for(int i=0; i < syms[0].table_size; i++){
            if(syms[i].st_name != 0) printf(" %016lx %016lx %-7s %-7s %-9s %s\n", syms[i].st_value, syms[i].st_size, get_symbole_type(syms[i].st_info), get_symbol_bind(syms[i].st_info), get_symbol_visibility(syms[i].st_other), syms[i].st_name);
        }
    };
    return syms;
}

Symbol64_Info *get_dynamic_symbol(u_int8_t* mem, Elf64_Ehdr *ehdr, int show){
    Elf64_Shdr dyn_syms_shdr;
    Symbol64_Info *dyn_syms;

    
    if(get_section(mem, ehdr, SHT_DYNSYM, &dyn_syms_shdr)){
        fprintf(stderr," No dynamic symbol found\n");
        return NULL;
    }
    dyn_syms = get_table(mem, ehdr, dyn_syms_shdr);
    if(show){
        printf("\nDynamic Symbol table :\n");
        printf("      %-16s  %-10s %-7s %-7s %s\n", "VALUE", "SIZE", "TYPE", "BIND", "NAME");
        for(int i=0; i < dyn_syms[0].table_size; i++){
            if(dyn_syms[i].st_name != 0) printf(" %016lx %016lx %-7s %-7s %s\n", dyn_syms[i].st_value, dyn_syms[i].st_size, get_symbole_type(dyn_syms[i].st_info), get_symbol_bind(dyn_syms[i].st_info), dyn_syms[i].st_name);
        }
    }
    
    return dyn_syms;
}

char *get_relo_type(uint64_t r_info){
    char *rel_type;
    switch (ELF64_R_TYPE(r_info))
    {
    case R_X86_64_NONE:         rel_type = "R_X86_64_NONE"; break;
    case R_X86_64_64:           rel_type = "R_X86_64_64"; break;
    case R_X86_64_PC32:         rel_type = "R_X86_64_PC32"; break;
    case R_X86_64_GOT32:        rel_type = "R_X86_64_GOT32"; break;
    case R_X86_64_PLT32:        rel_type = "R_X86_64_PLT32"; break;
    case R_X86_64_COPY:         rel_type = "R_X86_64_COPY"; break;
    case R_X86_64_GLOB_DAT:     rel_type = "R_X86_64_GLOB_DAT"; break;
    case R_X86_64_JUMP_SLOT:    rel_type = "R_X86_64_JUMP_SLOT"; break;
    case R_X86_64_RELATIVE:     rel_type = "R_X86_64_RELATIVE"; break;
    case R_X86_64_GOTPCREL:     rel_type = "R_X86_64_GOTPCREL"; break;
    case R_X86_64_32:           rel_type = "R_X86_64_32"; break;
    case R_X86_64_32S:          rel_type = "R_X86_64_32S"; break;
    case R_X86_64_16:           rel_type = "R_X86_64_16"; break;
    case R_X86_64_PC16:         rel_type = "R_X86_64_PC16"; break;
    case R_X86_64_8:            rel_type = "R_X86_64_8"; break;
    case R_X86_64_PC8:          rel_type = "R_X86_64_PC8"; break;
    default:                    rel_type = "Unknow"; break;
    }
    return rel_type;
}

int get_dynamic_relocation(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Shdr *rela_shdr;
    Elf64_Rela **rela;
    Symbol64_Info *dyn_syms;
    int count;

    printf("Dynamic Relocation records :\n");
    count = get_group_section(mem, ehdr, SHT_RELA, &rela_shdr);
    if(count < 1){
        fprintf(stderr," No dynamic relocation records found\n");
        return 1;
    }
    rela = (Elf64_Rela **)malloc(count * sizeof(Elf64_Rela *));
    if (rela == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    dyn_syms = get_dynamic_symbol(mem, ehdr, 0);
    for(int i = 0; i < count; i++){
        rela[i] = (Elf64_Rela *)&mem[rela_shdr[i].sh_offset]; 
    }
     printf("     %-11s %s %36s\n", "OFFSET", "TYPE", "SYMBOL-NAME + ADDEND");
    for(int i =0; i < count; i++){
        for(int j = 0; j < (int)TABLE_SIZE(rela_shdr[i]); j++){
            if(ELF64_R_SYM(rela[i][j].r_info)!=0){
                printf("%016lx %-20s %s + %ld\n", rela[i][j].r_offset, get_relo_type(rela[i][j].r_info), dyn_syms[ELF64_R_SYM(rela[i][j].r_info)].st_name, rela[i][j].r_addend);
            }else {
                printf("%016lx %-20s %ld\n", rela[i][j].r_offset, get_relo_type(rela[i][j].r_info), rela[i][j].r_addend);
            }    
        }
    }
    free(dyn_syms);
    free(rela_shdr);
    free(rela);
    return 0;
}

int get_relocation(u_int8_t* mem, Elf64_Ehdr *ehdr){
    Elf64_Shdr *rel_shdr;
    Elf64_Rel **rel;
    Symbol64_Info *dyn_syms;
    int count;

    printf("Relocation records :\n");
    count = get_group_section(mem, ehdr, SHT_REL, &rel_shdr);
    if(count < 1){
        fprintf(stderr," No relocation records found\n");
        return 1;
    }
    rel = (Elf64_Rel **)malloc(count * sizeof(Elf64_Rel *));
    if (rel == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    dyn_syms = get_dynamic_symbol(mem, ehdr, 0);
    for(int i = 0; i < count; i++){
        rel[i] = (Elf64_Rel *)&mem[rel_shdr[i].sh_offset]; 
    }
     printf("     %-11s %s %36s\n", "OFFSET", "TYPE", "SYMBOL-NAME");
    for(int i =0; i < count; i++){
        for(int j = 0; j < (int)TABLE_SIZE(rel_shdr[i]); j++){
            if(ELF64_R_SYM(rel[i][j].r_info)!=0){
                printf("%016lx %-20s %s\n", rel[i][j].r_offset, get_relo_type(rel[i][j].r_info), dyn_syms[ELF64_R_SYM(rel[i][j].r_info)].st_name);
            }else {
                printf("%016lx %-20s\n", rel[i][j].r_offset, get_relo_type(rel[i][j].r_info));
            }
        }
    }
    free(dyn_syms);
    free(rel_shdr);
    free(rel);
    return 0;
}

int elf_64_disass(Arguments args, u_int8_t* mem){
    Elf64_Ehdr *ehdr;
    Symbol64_Info *dyn_syms;
    Symbol64_Info *syms;
    int elf_type,elf_archi;

    ehdr = (Elf64_Ehdr *)mem;
    elf_type = get_elf_type(args.filename, ehdr);
    if(elf_type == 0) goto end;
    elf_archi = get_architecture(args.filename, ehdr);
    if(elf_archi == 0) goto end;
    print_format(args.filename, elf_type, elf_archi, ehdr->e_entry);
    if(elf_archi != EM_X86_64){
        fprintf(stderr, "%s : Architecture not implemented\n", args.filename);
        goto end;
    }
    if(args.all || args.all_headers || args.program_headers) get_program_header(mem, ehdr);
    if(args.all || args.all_headers || args.section_headers) get_section_header(mem, ehdr);
    if(args.all || args.syms){
        syms = get_symbol(mem, ehdr, 1);
        if(syms != NULL){
            free(syms);
        }
    }
    if(args.dynsyms){
        dyn_syms = get_dynamic_symbol(mem, ehdr, 1);
        if(dyn_syms != NULL){
            free(dyn_syms);
        }
    }
    if(args.reloc) get_relocation(mem, ehdr);
    if(args.dynreloc) get_dynamic_relocation(mem, ehdr);
end :
    return 0;
}