

static void print_time(double seconds)
{
    if(seconds < 60)
    {
        printf("%.2lf seconds\n", seconds);
    }
    else if(seconds < 3600)
    {
        printf("%.2lf minutes\n", seconds/ 60 );
    }
    else
    {
        printf("%.2lf hours\n", seconds/ 3600);
    }
}

static void print_secret_key(polyvec secret_key)
{
    for(uint8_t block_index = 0; block_index < KYBER_K; block_index++)
    {
        printf("Block: %d\n", block_index);
        for(uint16_t coeff_index = 0; coeff_index < KYBER_N; coeff_index++)
        {
            printf("coeff %3d: %2d\t", coeff_index, secret_key.vec[block_index].coeffs[coeff_index]);
        }
        printf("\n");
    }
}

static void print_status(int randomness_seed,
                         uint16_t parallel_level,
                         uint16_t nbrof_values_recovered_total,
                         int nbrof_queries,
                         time_t start,
                         time_t * curr_time)
{
    printf("\n\n");
    printf("Attacking %s...\n", CRYPTO_ALGNAME);
    printf("Seed for randomness: %d\n", randomness_seed);
    printf("Parallel level: %d\n", parallel_level);
    printf("  Coefficients recovered:  %d\n", nbrof_values_recovered_total);
    printf("\nQueries performed so far:   %d\n", nbrof_queries);
    printf("   out of %d in total =   %.1lf percent\n", KYBER_K * KYBER_N, (double)nbrof_values_recovered_total/(KYBER_K * KYBER_N)*100);
    printf("Est. nbrof queries needed: %.2lf\n", (double)(KYBER_K * KYBER_N)/nbrof_values_recovered_total * nbrof_queries);
    time(curr_time);
    double time_lapsed_seconds = difftime(*curr_time,start);
    printf("\nElapsed time: ");
    print_time(time_lapsed_seconds);
    double approx_time_needed = 0;
    if(nbrof_values_recovered_total != 0) approx_time_needed = time_lapsed_seconds / nbrof_values_recovered_total * (KYBER_K * KYBER_N);
    printf("   Est. time,\n");
    printf("        left: " );
    print_time( (approx_time_needed - time_lapsed_seconds));
    printf("       total: ");
    print_time(approx_time_needed);
}

static void print_query_set(int block_index,
                            int parallel_level,
                            state BRT[],
                            uint8_t coeff_BRT_state[KYBER_K][KYBER_N],
                            uint8_t query_set[])
{
    printf("\nBlock index = %d\n", block_index);
    printf("\ncoeff indexies in query set:\n");
    for(int i=0; i < parallel_level; i++)
    {
        printf("query_set[%d]\t= %d, ", i, query_set[i]);

        if(! BRT[coeff_BRT_state[block_index][query_set[i]]].finished)
        {
            printf("search state has h = %d\n",BRT[coeff_BRT_state[block_index][query_set[i]]].h);
        }
        else
        {
            printf("finished, value = %d\n",BRT[coeff_BRT_state[block_index][query_set[i]]].value);
            //printf(" %d \n", l);
            //printf("Correct value = %d\n", skpoly.vec[block_index].coeffs[query_set[i]]);
        }
    }
}

static void print_byte_array(unsigned char array[], int nbrof_bytes)
{
    #define ROW_WIDTH 8
    for(int i=0; i <= nbrof_bytes / ROW_WIDTH; i++)
    {
        for(int j=0; j<ROW_WIDTH ; j++){
            if (i*ROW_WIDTH + j < nbrof_bytes)
            printf(" 0x%02hhX ",  array[ i*ROW_WIDTH + j]);

        }
        printf("\n");
    }
}
