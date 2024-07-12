#include "args_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

Arguments parse_args(int argc, char *argv[]){
    Arguments args;
    args.all = 0;
    args.all_headers = 0;
    args.program_headers = 0;
    args.section_headers = 0;
    args.syms = 0;
    args.dynsyms = 0;
    args.dynreloc = 0;
    args.reloc = 0;
    args.filename = NULL;

    struct option long_options[] = {
        {"all", no_argument, NULL, 'a'},
        {"all-headers", no_argument, NULL, 'x'},
        {"program-headers", no_argument, NULL, 'P'},
        {"section-headers", no_argument, NULL, 'S'},
        {"syms", no_argument, NULL, 's'},
        {"dynamic-syms", no_argument, NULL, 'd'},
        {"dynamic-reloc", no_argument, NULL, 'R'},
        {"reloc", no_argument, NULL, 'r'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "axPSsdRr", long_options, NULL)) != -1) {
        switch (opt) {
            case 'a' :  args.all = 1; break;
            case 'x':   args.all_headers = 1; break;
            case 'P':   args.program_headers = 1; break;
            case 'S':   args.section_headers = 1; break;
            case 's':   args.syms = 1; break;
            case 'd':   args.dynsyms = 1; break;
            case 'R':   args.dynreloc = 1; break;
            case 'r':   args.reloc = 1; break;
            default:
                fprintf(stderr, "Usage: %s [-a/--all] [-x/--all-headers] [-P/--program-headers] [-S/--section-headers] [-s/--syms] [-d/--dynamic-syms] [-r, --reloc] [-R, --dynamic-reloc] <executable>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        args.filename = argv[optind];
    } else {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }

    return args;
}