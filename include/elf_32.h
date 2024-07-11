#include <elf.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "args_parse.h"

int elf_32_disass(Arguments args, u_int8_t* mem);