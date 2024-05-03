#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "adaptive_parallel_singlethread.h"

int
main(int argc, char *argv[])
{
    int opt;
    int prints_verbosity;
    int seed;
    bool cheat = false;
    uint16_t p_level;
    extern char *optarg;
    extern int optind;

    while ((opt = getopt(argc, argv, "s:p:v:c")) != -1) {
        switch (opt) {
            case 'p':
                p_level = atoi(optarg);
                break;
            case 's':
                seed = atoi(optarg);
                break;
            case 'v':
                prints_verbosity = atoi(optarg);
                break;
            case 'c':
                cheat = true;
                break;
        default: /* '?' */
            printf("Usage: %s -p parallel_level -s randomness_seed -v verbosity_level [-c]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

   adaptive_parallel_attack(seed, p_level, cheat, prints_verbosity);

   exit(EXIT_SUCCESS);
}
