#include <elf.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int elf_64_disass( char *filename, u_int8_t* mem);
uint16_t get_architecture(char *filename, Elf64_Ehdr *ehdr);
uint16_t get_elf_type(char *filename, Elf64_Ehdr *ehdr);
void print_format(char * filename, u_int8_t elf_type, u_int8_t elf_archi, Elf64_Addr elf_enry);
void parse_elf_header(u_int8_t* mem, Elf64_Ehdr *ehdr);
char *get_flags(uint32_t p_flags);