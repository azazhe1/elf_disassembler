#include <capstone/capstone.h>
#include "elf_64.h"

#define MAX_SECTION 200
#define MAX_PLT_SIZE 10000

typedef struct {
    uint64_t address;
    char mnemonic[32];
    char op_str[160];
    size_t size;
    uint8_t bytes[16];
    
}Instruction;

typedef struct {
    const char *name;
    int count_inst;
    Instruction *inst_list;

}Section;

typedef struct {
    const char *name;
    Elf64_Addr address;

}Plt;


int disass(u_int8_t* mem, Section64_Info *sections, Dynamic_Reloc *dyn_rela, Symbol64_Info *sym);
int count_section(Section64_Info *sections);
Section disass_section(u_int8_t* section_mem, Section64_Info section_inf, csh handle);
int count_inst_section(u_int8_t* section_mem, Section64_Info section_inf, csh handle);
void free_sections(Section *section_list, int nb_sections);
void show_section(Section *section_list, int nb_sections);
Plt *sanitize_plt(Section *plt, Dynamic_Reloc *dyn_rela);
const char *get_rela_name(Dynamic_Reloc *dyn_rela,Elf64_Addr address);
char *check_sym(uint64_t address, Symbol64_Info *syms);
char *check_plt(uint64_t address, Plt *plt_lis);
char *check_call(char *op_str, Plt *plt_list, Symbol64_Info *syms, int *is_plt);
char *check_jump(uint64_t last_res_addr, char *op_str, Plt *plt_list, Symbol64_Info *syms, int *is_plt, uint64_t *offset);