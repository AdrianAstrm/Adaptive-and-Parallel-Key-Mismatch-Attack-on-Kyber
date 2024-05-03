#include "binary_recovery_tree.h"

// Binary Recovery Tree for kyber1024


void set_up_BRT(struct state * BRT)
{

    BRT[STATE_1] = (struct state) {.finished       = false,
                                   .h              = 8,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_2, STATE_4}};

    BRT[STATE_2] = (struct state) {.finished       = false,
                                   .h              = 9,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_3, FIN_1}};

    BRT[STATE_3] = (struct state) {.finished       = false,
                                   .h              = 10,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_2, FIN_3}};

    BRT[STATE_4] = (struct state) {.finished       = false,
                                   .h              = 7,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_4, FIN_5}};

    BRT[FIN_1]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 0,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[FIN_2]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 2,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[FIN_3]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 1,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[FIN_4]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = -1,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[FIN_5]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = -2,
                                   .BRT_next_state = NOT_DEFINED};
}
