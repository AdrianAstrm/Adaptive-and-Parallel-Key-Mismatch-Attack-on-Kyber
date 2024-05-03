#include "binary_recovery_tree.h"

// Binary Recovery Tree for kyber768
//[STATE_1]:h = 4
//├── (oracle=0)-> [STATE_2]:h=5
//│   ├── (oracle=0)-> [STATE_3]:h=6
//│   │   ├── (oracle=0)-> value=2
//│   │   └── (oracle=1)-> value=1
//│   └── (oracle=1)-> value=0
//└── (oracle = 1)-> [STATE_4]:h=3
//    ├── (oracle=0)-> value=-1
//    └── (oracle=1)-> value=-2


void set_up_BRT(struct state * BRT)
{

    BRT[STATE_1] = (struct state) {.finished       = false,
                                   .h              = 4,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_2, STATE_4}};

    BRT[STATE_2] = (struct state) {.finished       = false,
                                   .h              = 5,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_3, FIN_1}};

    BRT[STATE_3] = (struct state) {.finished       = false,
                                   .h              = 6,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_2, FIN_3}};

    BRT[STATE_4] = (struct state) {.finished       = false,
                                   .h              = 3,
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
