#include <elf.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include "args_parse.h"

#define SUPPORTED_ARCHI_COUNT (int)(sizeof(SUPPORTED_ARCHI) / sizeof(SUPPORTED_ARCHI[0]))
#define TABLE_SIZE(shdr) ((shdr).sh_size / sizeof(Elf64_Sym))

typedef struct {
    Elf64_Addr st_value;
    Elf64_Xword st_size;
    unsigned char st_info;
    unsigned char st_other;
    char *st_name;
    int table_size;
} Symbol64_Info;


int elf_64_disass(Arguments args, u_int8_t* mem);
uint16_t get_architecture(char *filename, Elf64_Ehdr *ehdr);
uint16_t get_elf_type(char *filename, Elf64_Ehdr *ehdr);
void print_format(char * filename, u_int8_t elf_type, u_int8_t elf_archi, Elf64_Addr elf_enry);
void get_program_header(u_int8_t* mem, Elf64_Ehdr *ehdr);
void get_section_header(u_int8_t* mem, Elf64_Ehdr *ehdr);
char *get_ph_flags(uint32_t p_flags);
int get_power_2(uint64_t p_align);
Symbol64_Info *get_table(u_int8_t* mem, Elf64_Ehdr *ehdr, Elf64_Shdr syms_shdr);
Symbol64_Info *get_symbol(u_int8_t* mem, Elf64_Ehdr *ehdr, int show);
int  get_section(u_int8_t* mem, Elf64_Ehdr *ehdr, uint32_t value, Elf64_Shdr *result);
char *get_symbole_type(unsigned char st_info);
char *get_symbol_bind(unsigned char st_info);
char *get_symbol_visibility(unsigned char st_other);
int get_dynamic_relocation(u_int8_t* mem, Elf64_Ehdr *ehdr);
int get_group_section(u_int8_t* mem, Elf64_Ehdr *ehdr, uint32_t value, Elf64_Shdr **result);
Symbol64_Info *get_dynamic_symbol(u_int8_t* mem, Elf64_Ehdr *ehdr, int show);
char *get_relo_type(uint64_t r_info);
int get_relocation(u_int8_t* mem, Elf64_Ehdr *ehdr);