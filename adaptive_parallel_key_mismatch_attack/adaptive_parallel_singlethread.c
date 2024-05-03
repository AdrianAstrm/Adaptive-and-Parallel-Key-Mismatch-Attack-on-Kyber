 #include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
// #include <ctype.h>
#include <assert.h>
#include <time.h>

#include "api.h"
#include "indcpa.h"
#include "kem.h"
#include "rng.h"

#include "adaptive_parallel_singlethread.h"
#include "binary_recovery_tree.h"
#include "measure_attack.h"

#include "print_utils.c"

// check if msg tested by adversary equals the decrypted m_dec
bool oracle(unsigned char * msg, unsigned char * m_dec)
{
  for(int a = 0; a < KYBER_SYMBYTES; a++)
  {
    if(msg[a] != m_dec[a])
    {
      return false;
    }
  }
  return true;
}


int adaptive_parallel_attack_with_measurements(
                                    int randomness_seed,
                                    uint16_t parallel_level,
                                    bool cheat_when_searching,
                                    uint8_t prints_verbosity,
                                    single_run_measurement * measurement)
{
    assert(parallel_level>0 && parallel_level<=256);
    //if mode is not set to cheat the maximum parallel_level is 63
    if (!cheat_when_searching) assert(parallel_level < 64);


    /* random init */
    //unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    //srand(time(NULL));
    srand(randomness_seed);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);



    /*pk sk ct*/
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];

    // the secret key to be recovered
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    // the polyvec of true s of Alice
    polyvec             skpoly = { { 0 } };
    // the m set by adversary
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    //print_byte_array(m,KYBER_SYMBYTES);

    // get key pair
    if ( crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        exit(EXIT_FAILURE);
    }

    // for each coefficient in Alice secret key, s, (a search instance),
    // the recovery process has a state,
    // represented as an index in a binary recovery tree (BRT)
    #if KYBER_K == 2
    state BRT[13];
    #elif KYBER_K == 3 || KYBER_K == 4
    state BRT[9]; //BRT[9] is enough for kyber768 and kyber1024
    #endif

    //get the BRT for the current security level
    set_up_BRT(BRT);

    // the array below stores the state (in the BRT)
    // of each of the coefficients search instances
    uint8_t coeff_BRT_state[KYBER_K][KYBER_N] = {{0}};

    //Queue of coefficients to be attacked is a future query
    uint16_t queue_next_coeff = 0; // need to be more than 8 bits to reach >255 (indicate no more coeff in block)
    //uint16_t nbrof_coeff_left_in_block = KYBER_N; // 256

    //Set of coefficient, referenced by thier index in coeff_BRT_state,
    // to be targeted in the current/next query
    uint8_t query_set[parallel_level];

    // for keeping track of time left to wait
    time_t start, curr_time, end;
    time (&start);

    int nbrof_queries = 0;
    uint16_t nbrof_values_recovered_total = 0;

    for(int block_index = 0; block_index < KYBER_K; block_index++)
    {
        if(prints_verbosity>1) printf("\n\n\n------------NEXT BLOCK!-------------\n");

        // for cpu-time measurement
        clock_t begin_block = clock();
        // for partial recovery measurement
        uint16_t nbrof_values_recovered_this_block = 0;

        // Start by initiating the query-set before attacking next block
        // DEPRECATED: nbrof_coeff_left_in_block = KYBER_N;
        queue_next_coeff = 0;
        for(int i=0; i < parallel_level; i++)
        {
            query_set[i] = queue_next_coeff;
            queue_next_coeff ++;
            //DEPRECATED: nbrof_coeff_left_in_block --;
        }

        uint16_t nbrof_active_coeff =  parallel_level; //used for full recovery
        bool block_fully_recovered = false;
        // bools below for measurements
        bool block_partially_recovered = false;
        bool block_partially_recovered_measured = false;

        while (! block_fully_recovered)
        {
            if(prints_verbosity>0)
            {
                print_status(randomness_seed,
                             parallel_level,
                             nbrof_values_recovered_total,
                             nbrof_queries,
                             start,
                             &curr_time);
            }
            //loop and update h
            int8_t h[KYBER_N] = {0};
            //memset(h, 0, KYBER_N *sizeof(h[0]));
            for(int i=0; i < parallel_level; i++)
            {
                //set h for coefficients which are not found
                if(! BRT[coeff_BRT_state[block_index][query_set[i]]].finished)
                {
                    h[query_set[i]] = BRT[coeff_BRT_state[block_index][query_set[i]]].h;
                }
            }
            if(prints_verbosity>1) {
                print_query_set(block_index, parallel_level, BRT, coeff_BRT_state, query_set);
            }

            //Perform new Attack Query
            nbrof_queries += 1;    // count queries

            measurement->blocks_full_recovery[block_index].nbrof_queries += 1;
            if (!block_partially_recovered) measurement->blocks_partial_recovery[block_index].nbrof_queries += 1;

            if(prints_verbosity>1) printf("\n\nPerforming new Attack Query (number %d)\n", nbrof_queries);

            //make the cryptotext from the set of h
            kemenc_Attack(ct, m, pk, h, block_index);

            //decrypt the ct, as Alice would do
            unsigned char m_dec[KYBER_SYMBYTES] = { 0 };
            //m_dec is not known to the Adversary, but used by the oracle
            //having access to m_dec in this function simplifies "cheating" (read more below)
            indcpa_dec(m_dec, ct, sk);

            // Now loop through all appropriate m and test
            uint64_t counter;
            uint64_t counter_roof_value = 1ull << nbrof_active_coeff; // 2^nbrof_active_coeff different m to test

            bool found_no_matching_m = true; //safetycheck

            if(prints_verbosity>1) printf("\nSearching for matching m...\n");
            for (counter = 0;counter < counter_roof_value; counter++)
            {
                if(prints_verbosity> 3) printf("\n\nCounter = %d", counter);

                measurement->blocks_full_recovery[block_index].nbrof_search_operations += 1;
                if (!block_partially_recovered)
                {
                    measurement->blocks_partial_recovery[block_index].nbrof_search_operations += 1;
                }

                memset(m, 0, KYBER_SYMBYTES);

                //pick the bits from counter
                // and modify m at bit-places
                // corresponding to the indexies of the coefficients
                int c_bit = 0;
                for(int i=0; i < parallel_level; i++)
                {
                    // if a coeff is active
                    if( ! BRT[coeff_BRT_state[block_index][query_set[i]]].finished )
                    {
                        //set the next bit from counter at the correct index in m
                        unsigned long mask = 0x1 << c_bit;
                        if((counter & mask) != 0)
                        {
                            //printf("\ncounter & mask is %d", counter & mask);
                            m[query_set[i] / 8] |= (0x1 << query_set[i] % 8);
                        }
                        //else printf("\ncounter & mask is zero");
                        c_bit ++;
                    }
                }
                if(prints_verbosity> 3)
                {
                    printf("\ntesting m = \n");
                    print_byte_array(m, KYBER_SYMBYTES);
                    printf("\ncorrect m is \n");
                    print_byte_array(m_dec, KYBER_SYMBYTES);
                }

                if(cheat_when_searching)
                {
                    //cheating when searching will skip the need for searching by seting m = m_dec directly
                    indcpa_dec(m, ct, sk);
                }
                if (oracle(m,m_dec))
                {
                    if(prints_verbosity>1)
                    {
                        printf("\n\nFound match for m =  \n");
                        print_byte_array(m, KYBER_SYMBYTES);
                        printf("..after %d tries (search-operations this query)\n", counter+1);
                        printf("\nUpdating coefficients' states, h for next query...\n");
                    }
                    //found the correct m
                    //loop through query_set
                    //and update coeff states according to the bits in m
                    uint8_t nbrof_values_found_this_query = 0;
                    for(int l=0; l < parallel_level; l++)
                    {
                        //printf("\nlooking at coeff at index = %d", query_set[l]);
                        // if a coeff is active
                        if( ! BRT[coeff_BRT_state[block_index][query_set[l]]].finished )
                        {
                            //look at the correct place in m
                            int byte_index = query_set[l] / 8;
                            uint8_t byte_mask = (0x1 << query_set[l] % 8);
                            int next_state_bit;
                            //the bit is either zero or one...
                            (m[byte_index] & byte_mask) == 0 ? (next_state_bit = 0) : (next_state_bit = 1);


                            //and the next
                            //state of the coefficient search
                            //can be found in the BRT
                            coeff_BRT_state[block_index][query_set[l]] =
                            BRT[coeff_BRT_state[block_index][query_set[l]]].BRT_next_state[next_state_bit];

                            //if it is now finished,
                            //put the next coeff from queue in the query_set
                            if (BRT[coeff_BRT_state[block_index][query_set[l]]].finished)
                            {
                                nbrof_values_found_this_query++;
                                recs[block_index][query_set[l]] = BRT[coeff_BRT_state[block_index][query_set[l]]].value;
                                //printf("\nfound value: %d, of coeff at index = %d, in block = %d\n", recs[block_index][query_set[l]], query_set[l], block_index);
                                //printf("\ncorrect value = %d\n",skpoly.vec[block_index].coeffs[query_set[l]]);

                                assert(recs[block_index][query_set[l]] == skpoly.vec[block_index].coeffs[query_set[l]]);
                                //replace the finished coefficient with a new from the queue
                                if( queue_next_coeff < KYBER_N) //nbrof_coeff_left_in_block > 0)
                                {
                                    query_set[l] = queue_next_coeff;
                                    queue_next_coeff ++;
                                    //nbrof_coeff_left_in_block --;
                                }
                                else
                                {
                                    if(!block_partially_recovered)
                                    {
                                        block_partially_recovered = true;
                                        clock_t end_block_part = clock();
                                        measurement->blocks_partial_recovery[block_index].cpu_time =
                                             (double)(end_block_part - begin_block) / CLOCKS_PER_SEC;
                                    }

                                    // reduce the number of active coeff in query_set if there is no more new in queue
                                    nbrof_active_coeff --;
                                    // check if block i done
                                    bool temp_bool = true;
                                    for(int n=0; n < parallel_level; n++){
                                        if (! BRT[coeff_BRT_state[block_index][query_set[n]]].finished)
                                        {
                                            temp_bool = false;
                                        }
                                    }
                                    block_fully_recovered = temp_bool;
                                }

                            }// end coeff finished after state change?
                        }// end coeff still active?

                    }// end loop all coeffs in query_set

                    nbrof_values_recovered_total += nbrof_values_found_this_query;
                    if(prints_verbosity>1) printf("\nRecovered the value of %d coefficient(s) from the recent query\n", nbrof_values_found_this_query);

                    nbrof_values_recovered_this_block += nbrof_values_found_this_query;
                    //measure recovered coeffs
                    if(block_fully_recovered) measurement->blocks_full_recovery[block_index].nbrof_coeff_recovered = nbrof_values_recovered_this_block;
                    if(block_partially_recovered && !block_partially_recovered_measured)
                    {
                        measurement->blocks_partial_recovery[block_index].nbrof_coeff_recovered =
                                                          nbrof_values_recovered_this_block;
                        block_partially_recovered_measured = true;
                    }
                    //safety check,
                    // indicates that the oracle returned true for some m
                    found_no_matching_m = false;
                    // break when found correct m
                    break; // breaks the searching loop

                }// end if (oracle(..., m))

                if(prints_verbosity> 3) printf("\nNot a match\n");

            } //end search-loop (counter++)

            //safety check
            assert(! found_no_matching_m );


        }//end current block loop
        clock_t end_block_full = clock();
        measurement->blocks_full_recovery[block_index].cpu_time =
                    (double)(end_block_full - begin_block) / CLOCKS_PER_SEC;
    }//end loop of the blocks
    time(&end);


    // print summary
    printf("\nAttack done");
    if(cheat_when_searching) printf(" (cheated)");
    printf(".\nSeed for randomness was: %d, ", randomness_seed);
    printf("Parallel level = %d, ", parallel_level);
    printf("Total nbrof queries: %d\n", nbrof_queries);

    if(prints_verbosity>0)
    {
        double t_diff = difftime(end,start);
        printf("Elasped time: %.2lf seconds.\n", t_diff );
        printf("Elasped time: ");

        print_time(t_diff);
    }

    return nbrof_queries;
}

int adaptive_parallel_attack(int randomness_seed,
                            uint16_t parallel_level,
                            bool cheat_when_searching,
                            uint8_t prints_verbosity)
{
    single_run_measurement dummy_measurement;
    return adaptive_parallel_attack_with_measurements(randomness_seed,
                                                      parallel_level,
                                                      cheat_when_searching,
                                                      prints_verbosity,
                                                      &dummy_measurement);
}
