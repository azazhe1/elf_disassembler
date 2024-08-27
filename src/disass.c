#include "disass.h"
#include <stdio.h>
#include <stdlib.h>


int count_inst_section(u_int8_t* section_mem, Section64_Info section_inf, csh handle){
    cs_insn *insn;
    size_t count = 0;
    uint64_t read_size = 0;
    int size = 0;

    while(read_size < section_inf.sh_size){
        count = cs_disasm(handle, section_mem + read_size, section_inf.sh_size - read_size, section_inf.sh_offset + read_size, 0, &insn);
        if(count > 0){
            size++;
            for(size_t i = 0; i < count; i++) {
                read_size += insn[i].size;
            }
            size += count;
            cs_free(insn, count);
        }
        else {
            size ++;
            read_size ++;
        }
    }
    return size;
}

Section disass_section(u_int8_t* section_mem, Section64_Info section_inf, csh handle){
    Section section;
    int count_max_inst = count_inst_section(section_mem, section_inf, handle);
    cs_insn *insn;
    size_t count;
    uint64_t read_size = 0;
    int index = 0;
    int bad = -1;
    section.name = section_inf.sh_name;
    section.count_inst = count_max_inst;
    section.inst_list = malloc(sizeof(Instruction)*(count_max_inst+1));
    
    while(read_size < section_inf.sh_size){
        count = cs_disasm(handle, section_mem + read_size, section_inf.sh_size - read_size, section_inf.sh_offset + read_size, 0, &insn);
        if(count > 0){
            if (bad > -1){
                index++;
            }
            for(size_t i = 0; i < count; i++) {
                section.inst_list[index].address = insn[i].address;
                section.inst_list[index].size = insn[i].size;
                strcpy(section.inst_list[index].mnemonic, insn[i].mnemonic);
                strcpy(section.inst_list[index].op_str, insn[i].op_str);
                for(size_t j = 0; j < insn[i].size; j++){
                    section.inst_list[index].bytes[j] = insn[i].bytes[j];
                }
                read_size += insn[i].size;
                index++;
            }
            bad = -1;
            cs_free(insn, count);
        }else{
            bad++;
            if (bad == 0){// On ajoute une instruction bad
                section.inst_list[index].address = section_inf.sh_offset + read_size;
                strcpy(section.inst_list[index].mnemonic, "");
                strcpy(section.inst_list[index].op_str, "");
            }
            section.inst_list[index].size = bad + 1;
            section.inst_list[index].bytes[bad] = section_mem[read_size];
            
            read_size++;
        }
    }
    section.count_inst = index;
    return section;
}

int count_section(Section64_Info *sections_inf){
    int count = 0;
    while(sections_inf[count].sh_name != 0){
        count++;
    }
    return count;
}

void free_sections(Section *section_list, int nb_sections){
    for (int i = 0; i < nb_sections; i++){
        free(section_list[i].inst_list);
    }
}

void show_section(Section *section_list, int nb_sections){
    for(int i = 0; i < nb_sections; i++){
        printf("_disass section %s :\n", section_list[i].name);
        for(int j = 0; j < section_list[i].count_inst; j++){
            printf("0x%"PRIx64": ", section_list[i].inst_list[j].address);
            for (size_t k = 0; k < section_list[i].inst_list[j].size ; k++){
                 printf("%02x ",section_list[i].inst_list[j].bytes[k]);
            }
            if(section_list[i].inst_list[j].mnemonic[0] != '\0') printf("\t%s\t\t%s\n", section_list[i].inst_list[j].mnemonic, section_list[i].inst_list[j].op_str);
            else printf("(bad)\n");
        }
    }
}


const char *get_rela_name(Dynamic_Reloc *dyn_rela,Elf64_Addr address){
    int index = 0;
    const char *res = NULL;

    while(dyn_rela[index].dr_name != NULL){
        if(dyn_rela[index].address == address){
            res = dyn_rela[index].dr_name;
            break;
        }
        index++;
    }
    return res;
}

Plt *sanitize_plt(Section *plt, Dynamic_Reloc *dyn_rela){
    Plt *plt_list =  malloc(MAX_PLT_SIZE*sizeof(Plt));
    int plt_index = 0;
    uint64_t offset;
    Elf64_Addr address;
    const char *rela_name = NULL;
    int index_section = 0;

    while(plt[index_section].name != NULL){
        for(int i = 0; i < plt[index_section].count_inst; i++){
            if(plt_index >= MAX_PLT_SIZE){
                perror("plt too big\n");
                exit(EXIT_FAILURE);
            }
            if(!strcmp(plt[index_section].inst_list[i].mnemonic, "endbr64") && strstr(plt[index_section].inst_list[i+1].mnemonic, "jmp") && !strcmp(plt[index_section].inst_list[i+2].mnemonic, "nop")){
                if (sscanf(plt[index_section].inst_list[i+1].op_str, "qword ptr [rip + 0x%lx]", &offset) == 1) {
                    address = (Elf64_Addr) (offset+plt[index_section].inst_list[i+2].address);
                    rela_name = get_rela_name(dyn_rela, address);
                    if(rela_name != NULL){
                        plt_list[plt_index].name = rela_name;
                        plt_list[plt_index].address = plt[index_section].inst_list[i].address;
                        plt_index++;
                    }
                }
                i+=2;
            }
        }
        index_section++;
    }
    plt_list[plt_index].name = NULL;
    plt_list[plt_index].address = 0;
    return plt_list;
}

char *check_sym(uint64_t address, Symbol64_Info *syms){
    if (syms == NULL) return NULL;
    for(int i=0; i < syms[0].table_size; i++){
        if(syms[i].st_value == address) return syms[i].st_name;
    }
    return NULL;
}

char *check_plt(uint64_t address, Plt *plt_list){
    int i = 0;
    if(plt_list == NULL) return NULL;
    while(plt_list[i].name != NULL){
        if(address == plt_list[i].address) return (char *)plt_list[i].name;
        i++;
    }
    return NULL;
}

char *check_call(char *op_str, Plt *plt_list, Symbol64_Info *syms, int *is_plt){
    uint64_t address;
    char *res = NULL;

    if(strlen(op_str)<2 || op_str[0] != '0') goto end;
    address = strtoul(op_str, NULL, 16);
    if((res = check_plt(address, plt_list)) != NULL) *is_plt = 1;
    else if((res = check_sym(address, syms)) != NULL) *is_plt = 0;
end:
    return res;
}

char *check_jump(uint64_t last_res_addr, char *op_str, Plt *plt_list, Symbol64_Info *syms, int *is_plt, uint64_t *offset){
    uint64_t address;
    char *res = NULL;

    if(strlen(op_str)<2 || op_str[0] != '0') goto end;
    address = strtoul(op_str, NULL, 16);
    *offset = address-last_res_addr;
    if((res = check_plt(last_res_addr, plt_list)) != NULL) *is_plt = 1;
    else if((res = check_sym(last_res_addr, syms)) != NULL) *is_plt = 0;
end :
    return  res;

}

void show_disass(Section *section_list, int nb_sections, Plt *plt_list, Symbol64_Info *sym){
    char *res;
    size_t max_bytes = 8;
    size_t k;
    uint64_t last_res_addr = 0;
    int is_plt;
    uint64_t offset;

    for(int i = 0; i < nb_sections; i++){
        printf("\nDisassembly of the %s section:\n", section_list[i].name);
        for(int j = 0; j < section_list[i].count_inst; j++){
            if((res = check_sym(section_list[i].inst_list[j].address, sym)) != NULL){
                printf("\n%016lx <%s> :\n", section_list[i].inst_list[j].address, res); 
                last_res_addr = section_list[i].inst_list[j].address;
            }
            if((res = check_plt(section_list[i].inst_list[j].address, plt_list)) != NULL){
                printf("\n%016lx <%s@plt> :\n", section_list[i].inst_list[j].address, res);
                last_res_addr = section_list[i].inst_list[j].address;
            }
            printf(" %8lx: ", section_list[i].inst_list[j].address);
            for (k = 0; k < section_list[i].inst_list[j].size ; k++){
                if( section_list[i].inst_list[j].size >= max_bytes) break;//On affiche pas plus de max_bytes
                printf("%02x ",section_list[i].inst_list[j].bytes[k]);
            }
            for (size_t m = 0; m < (max_bytes - k); m++) {
                printf("   ");
            }
            if(section_list[i].inst_list[j].mnemonic[0] != '\0'){
                printf("%-8s\t%s", section_list[i].inst_list[j].mnemonic, section_list[i].inst_list[j].op_str);
                if(!strcmp(section_list[i].inst_list[j].mnemonic, "call")){
                    if((res = check_call(section_list[i].inst_list[j].op_str, plt_list, sym, &is_plt)) != NULL){
                        if(is_plt) printf(" <%s@plt>", res);
                        else printf(" <%s>", res);
                    }
                }else if(section_list[i].inst_list[j].mnemonic[0] == 'j'){
                    if((res = check_jump(last_res_addr, section_list[i].inst_list[j].op_str, plt_list, sym, &is_plt, &offset)) != NULL){
                        if(is_plt) printf(" <%s@plt+0x%lx>", res, offset);
                        else printf(" <%s+0x%lx>", res, offset);
                    }
                }
            }else printf("%-8s", "(bad)");
            printf("\n");
        }
    }
}

int disass(u_int8_t* mem, Section64_Info *sections_inf, Dynamic_Reloc *dyn_rela, Symbol64_Info *sym){
    csh handle;
    int nb_sections = count_section(sections_inf);
    int index = 0;
    Section section_list[MAX_SECTION];
    Section section_plt[MAX_SECTION];
    int section_plt_index = 0;
    Plt *plt_list = NULL;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    while(index < nb_sections){
        section_list[index] = disass_section(&mem[sections_inf[index].sh_offset], sections_inf[index], handle);
        index ++;
    }
    
    for(int i = 0; i < nb_sections; i++){
        if(strstr(section_list[i].name, ".plt.") != NULL){
            section_plt[section_plt_index] = section_list[i];
            section_plt_index++;
        }
    }
    section_plt[section_plt_index].name = NULL;
    plt_list = sanitize_plt(section_plt, dyn_rela);
    show_disass(section_list, nb_sections, plt_list, sym);
    if(plt_list) free(plt_list);
    free_sections(section_list, nb_sections);
    cs_close(&handle);
    return 0;
}