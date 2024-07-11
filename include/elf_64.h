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

int elf_64_disass(Arguments args, u_int8_t* mem);
uint16_t get_architecture(char *filename, Elf64_Ehdr *ehdr);
uint16_t get_elf_type(char *filename, Elf64_Ehdr *ehdr);
void print_format(char * filename, u_int8_t elf_type, u_int8_t elf_archi, Elf64_Addr elf_enry);
void get_program_header(u_int8_t* mem, Elf64_Ehdr *ehdr);
void get_section_header(u_int8_t* mem, Elf64_Ehdr *ehdr);
char *get_ph_flags(uint32_t p_flags);
int get_power_2(uint64_t p_align);
int get_sym_table(u_int8_t* mem, Elf64_Ehdr *ehdr);
int  get_section(u_int8_t* mem, Elf64_Ehdr *ehdr, uint32_t value, Elf64_Shdr *result);
char *get_symbole_type(unsigned char st_info);
char *get_symbole_bind(unsigned char st_info);
char *get_symbole_visibility(unsigned char st_other);