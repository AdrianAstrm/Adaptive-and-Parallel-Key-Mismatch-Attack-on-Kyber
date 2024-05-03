#ifndef MEASURE_ATTACK_H
#define MEASURE_ATTACK_H

#include "api.h"
//#include <stdint.h>

typedef struct blk_measurement{
    uint8_t block_index;
    unsigned int nbrof_queries;
    double cpu_time;
    unsigned long long nbrof_search_operations;
    unsigned int nbrof_coeff_recovered;
    double coeff_per_queries;
} block_measurement;


typedef struct {
    //uint16_t parallel_level;
    int seed;
    block_measurement blocks_partial_recovery[KYBER_K];
    block_measurement blocks_partial_recovery_total;
    block_measurement blocks_full_recovery[KYBER_K];
    block_measurement blocks_full_recovery_total;
} single_run_measurement;


#endif
