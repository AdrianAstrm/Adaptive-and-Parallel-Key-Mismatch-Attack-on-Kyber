#ifndef ADAPTIVE_PARALLEL_SINGLETHREAD_H
#define ADAPTIVE_PARALLEL_SINGLETHREAD_H



#include <stdint.h>
#include <stdbool.h>

#include "measure_attack.h"

bool oracle(unsigned char * msg_A, unsigned char * m_dec);

int adaptive_parallel_attack_with_measurements(
                                    int randomness_seed,
                                    uint16_t parallel_level,
                                    bool cheat_when_searching,
                                    uint8_t prints_verbosity,
                                    single_run_measurement * measurement);

int adaptive_parallel_attack(int randomness_seed,
                            uint16_t parallel_level,
                            bool cheat_when_searching,
                            uint8_t prints_verbosity);

#endif
