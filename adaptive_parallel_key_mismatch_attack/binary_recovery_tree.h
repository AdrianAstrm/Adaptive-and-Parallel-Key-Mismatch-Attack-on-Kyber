#ifndef BINARY_RECOVERY_TREE_H
#define BINARY_RECOVERY_TREE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct state{
    bool finished;
    uint8_t h;
    int8_t value;
    uint8_t BRT_next_state[2];
} state;
#define NOT_DEFINED 254
#define STATE_1 0
#define STATE_2 1
#define STATE_3 2
#define STATE_4 3
#define FIN_1 4
#define FIN_2 5
#define FIN_3 6
#define FIN_4 7
#define FIN_5 8


void set_up_BRT(struct state * BRT);

#endif
