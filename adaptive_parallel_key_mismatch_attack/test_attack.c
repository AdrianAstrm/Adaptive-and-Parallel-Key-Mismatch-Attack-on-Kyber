#include <stdio.h>
#include <assert.h>

#include "api.h"

#include "adaptive_parallel_singlethread.h"

#define NBROFTEST_SEEDS 4
#define NBROFTESTS_PARALLEL_LEVEL 4

struct test_fasit
{
    int seed;
    int nbrof_queries[NBROFTESTS_PARALLEL_LEVEL];
};

#if KYBER_K == 2
//regression tests for Kyber512
struct test_fasit expected_nbrof_queries[NBROFTEST_SEEDS] = {
                                {.seed = 1,      .nbrof_queries = {1329, 667, 446, 335}},
                                {.seed = 123,    .nbrof_queries = {1310, 656, 439, 330}},
                                {.seed = 4231,   .nbrof_queries = {1308, 657, 439, 330}},
                                {.seed = 654321, .nbrof_queries = {1319, 662, 442, 333}}
};

#elif KYBER_K == 3
//regression tests for Kyber768
struct test_fasit expected_nbrof_queries[NBROFTEST_SEEDS] = {
                                {.seed = -2,  .nbrof_queries = {1775, 889, 594, 447}},
                                {.seed = 0,   .nbrof_queries = {1758, 880, 588, 443}},
                                {.seed = 71,   .nbrof_queries = {1786, 895, 597, 450}},
                                {.seed = 123,  .nbrof_queries = {1758, 881, 589, 443}}
};
#elif KYBER_K == 4
//regression tests for Kyber1024
struct test_fasit expected_nbrof_queries[NBROFTEST_SEEDS] = {
                                {.seed = -32,  .nbrof_queries = {2410, 1209, 806, 605}},
                                {.seed = -1,   .nbrof_queries = {2369, 1187, 794, 596}},
                                {.seed = 0,    .nbrof_queries = {2350, 1177, 786, 592}},
                                {.seed = 9,    .nbrof_queries = {2367, 1186, 791, 595}}
};
#endif


bool run_regression_tests(){

    uint8_t prints_verbosity = 0;
    for(int i=0; i<NBROFTEST_SEEDS; i++)
    {
        for(uint8_t p_level=1; p_level<=NBROFTESTS_PARALLEL_LEVEL; p_level++)
        {
            //without cheating
            int nbrof_queries = adaptive_parallel_attack(expected_nbrof_queries[i].seed,
                                                         p_level,
                                                         false,
                                                         (prints_verbosity = 0));
            assert(nbrof_queries == expected_nbrof_queries[i].nbrof_queries[p_level-1]);
            //cheating
            nbrof_queries    = adaptive_parallel_attack(expected_nbrof_queries[i].seed,
                                                         p_level,
                                                         true,
                                                         (prints_verbosity = 0));
            assert(nbrof_queries == expected_nbrof_queries[i].nbrof_queries[p_level-1]);
        }
    }

    return true;
}

int main(int argc, char * argv[])
{
     //run regression tests
    printf("\nRunning regression tests for %s...\n", CRYPTO_ALGNAME);

    if (run_regression_tests())
    {
        printf("\n...passed all regression tests for %s.\n\n", CRYPTO_ALGNAME);
    }
    else
    {
        printf("\n...something went wrong.\a\n\n");
    }
}
