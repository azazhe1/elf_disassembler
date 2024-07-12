#ifndef ARGS_PARSE_H
#define ARGS_PARSE_H

typedef struct {
    int all;
    int all_headers;
    int program_headers;
    int section_headers;
    int syms;
    int dynsyms;
    int dynreloc;
    int reloc;
    char *filename;
} Arguments;

Arguments parse_args(int argc, char *argv[]);

#endif // ARGS_PARSE_H