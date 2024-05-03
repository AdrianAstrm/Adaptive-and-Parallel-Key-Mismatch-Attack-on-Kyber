#include "binary_recovery_tree.h"
//extra states for kyber512
#define STATE_5 9
#define STATE_6 10
#define FIN_6 11
#define FIN_7 12

// Binary Recovery Tree for kyber512
// Optimal in average case
//(h = 5) [STATE_1]
//├── (oracle=0): [STATE_2], (h=6)
//│   ├── (oracle=0):[STATE_3],(h=7)
//│   │    ├── (oracle=0):[FIN_1], (value=3)
//│   │    └── (oracle=1):[FIN_2], (value=2)
//│   └── (oracle=1):[FIN_3] (value=1)
//└── (oracle = 1):[STATE_4], (h=4)
//    ├── (oracle=0):[FIN_4], (value=0)
//    └── (oracle=1):[STATE_5], (h=3)
//        ├── (oracle=0):[FIN_5] (value=-1)
//        └── (oracle=1):[STATE_6] (h=2)
//            ├── (oracle=0):[FIN_6] (value=-2)
//            └── (oracle=1):[FIN_7] (value=-3)

void set_up_BRT(struct state * BRT)
{
    BRT[STATE_1] = (struct state) {.finished       = false,
                                   .h              = 5,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_2, STATE_4}};

    BRT[STATE_2] = (struct state) {.finished       = false,
                                   .h              = 6,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {STATE_3, FIN_3}};

    BRT[STATE_3] = (struct state) {.finished       = false,
                                   .h              = 7,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_1, FIN_2}};

    BRT[FIN_1]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 3,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[FIN_2]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 2,
                                   .BRT_next_state = NOT_DEFINED};
    BRT[FIN_3]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 1,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[STATE_4] = (struct state) {.finished       = false,
                                   .h              = 4,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_4, STATE_5}};

    BRT[FIN_4]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = 0,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[STATE_5] = (struct state) {.finished       = false,
                                   .h              = 3,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_5, STATE_6}};

    BRT[FIN_5]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = -1,
                                   .BRT_next_state = NOT_DEFINED};

    BRT[STATE_6] = (struct state) {.finished       = false,
                                   .h              = 2,
                                   .value          = NOT_DEFINED,
                                   .BRT_next_state = {FIN_6, FIN_7}};

    BRT[FIN_6]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = -2,
                                   .BRT_next_state = NOT_DEFINED};
    BRT[FIN_7]   = (struct state) {.finished       = true,
                                   .h              = NOT_DEFINED,
                                   .value          = -3,
                                   .BRT_next_state = NOT_DEFINED};

}
