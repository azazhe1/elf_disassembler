#include <stdio.h>
#include <stdlib.h>
#include "elf_64.h"
#include "elf_32.h"
#include "args_parse.h"

int elf_class(char *filename, uint8_t *mem){
    if (mem[EI_MAG0] != 0x7f || mem[EI_MAG1] != 'E' || mem[EI_MAG2] != 'L' || mem[EI_MAG3] != 'F'){
        fprintf(stderr,"%s is not an ELF file\n",filename);
        return -1;
    }
    if (mem[EI_CLASS] == ELFCLASSNONE ){
        fprintf(stderr,"%s : Invalid class, must be 32 or 64 bits\n",filename);
        return -2;
    }
    return mem[EI_CLASS];
}

int elf_disass(Arguments args){
    int fd = open(args.filename,O_RDONLY);
    struct stat st;
    uint8_t *mem;
    if(fd < 0){
        perror("open");
        exit(EXIT_FAILURE);
    }

    if(fstat(fd,&st) < 0){
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if(st.st_size>10000000){
        fprintf(stderr,"%s : File too big\n",args.filename);
        close(fd);
        exit(EXIT_FAILURE);
    }
    mem = mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(mem == MAP_FAILED){
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    switch (elf_class(args.filename, mem)){
    case ELFCLASS64:
        elf_64_disass(args, mem);
        break;
    case ELFCLASS32:
        elf_32_disass(args, mem);
        break;
    default:
        goto end;
        break;
    }

end :
    close(fd);
    munmap(mem,st.st_size);
    return 0;
}

int main(int argc, char *argv[]){
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-a/--all] [-x/--all-headers] [-P/--program-headers] [-S/--section-headers] [-s/--syms] [-d/--dynamic-syms] <executable>\n", argv[0]);
        return 1;
    }
    Arguments args = parse_args(argc, argv);
    elf_disass(args);
    
    return 1;
}


