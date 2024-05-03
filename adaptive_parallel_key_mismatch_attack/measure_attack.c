#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>


#include "measure_attack.h"
#include "adaptive_parallel_singlethread.h"

//void init_measurement(single_run_measurement * measurement){}


void print_measurement_to_file(FILE * datafile, single_run_measurement * measurement)
{
    //partiall recovery
    fprintf(datafile, "%3d\tPart.\t", measurement->seed);
    for(uint8_t block_index = 0; block_index < KYBER_K; block_index ++)
    {
        fprintf(datafile, "\t%d\t%3d\t%9.5lf\t%8d\t%d\t%.3lf\t",
                          measurement->blocks_partial_recovery[block_index].block_index,
                          measurement->blocks_partial_recovery[block_index].nbrof_queries,
                          measurement->blocks_partial_recovery[block_index].cpu_time,
                          measurement->blocks_partial_recovery[block_index].nbrof_search_operations,
                          measurement->blocks_partial_recovery[block_index].nbrof_coeff_recovered,
                          measurement->blocks_partial_recovery[block_index].coeff_per_queries);
    }
    // partial recoveryTotal
    fprintf(datafile, "\t\t%3d\t%9.5lf\t%8d\t%d\t%.3lf\n",
                        measurement->blocks_partial_recovery_total.nbrof_queries,
                        measurement->blocks_partial_recovery_total.cpu_time,
                        measurement->blocks_partial_recovery_total.nbrof_search_operations,
                        measurement->blocks_partial_recovery_total.nbrof_coeff_recovered,
                        measurement->blocks_partial_recovery_total.coeff_per_queries);


    //full recovery
    fprintf(datafile, "%3d\tFull\t", measurement->seed);
    for(uint8_t block_index = 0; block_index < KYBER_K; block_index ++)
    {
        fprintf(datafile, "\t%d\t%3d\t%9.5lf\t%8d\t%d\t%.3lf\t",
                          measurement->blocks_full_recovery[block_index].block_index,
                          measurement->blocks_full_recovery[block_index].nbrof_queries,
                          measurement->blocks_full_recovery[block_index].cpu_time,
                          measurement->blocks_full_recovery[block_index].nbrof_search_operations,
                          measurement->blocks_full_recovery[block_index].nbrof_coeff_recovered,
                          measurement->blocks_full_recovery[block_index].coeff_per_queries);
    }
    // full recovery Total
    fprintf(datafile, "\t\t%3d\t%9.5lf\t%8d\t%d\t%.3lf\n",
                        measurement->blocks_full_recovery_total.nbrof_queries,
                        measurement->blocks_full_recovery_total.cpu_time,
                        measurement->blocks_full_recovery_total.nbrof_search_operations,
                        measurement->blocks_full_recovery_total.nbrof_coeff_recovered,
                        measurement->blocks_full_recovery_total.coeff_per_queries);

}

void write_averages(char * path,
                    char * full_or_partial,
                    uint16_t parallel_level,
                    double average_nbrof_queries,
                    double average_cpu_time,
                    double average_nbrof_search_operations,
                    double average_nbrof_coeff_recovered,
                    double average_coeff_per_query,
                    double teoretical )
{
    FILE * average_file;
    char filename[128];
    sprintf(filename, "%s%s_averages_%s.txt",
                            path, CRYPTO_ALGNAME, full_or_partial);

    average_file = fopen(filename, "a");
    if (average_file == NULL) {
        printf("\nError: the average-file could not be opened\n");
        exit(EXIT_FAILURE);
    }

    fprintf(average_file, "%3d\t%8.3lf\t%10.5lf\t%5.3e\t%.4lf\t%.6lf\t%.6lf\n",
                           parallel_level,
                           average_nbrof_queries,
                           average_cpu_time,
                           average_nbrof_search_operations,
                           average_nbrof_coeff_recovered,
                           average_coeff_per_query,
                           (parallel_level / teoretical));
    //close file
    fclose(average_file);
}

int main(int argc, char * argv[])
{
    int opt;
    bool cheat = false;
    int parallel_level;
    extern char *optarg;
    extern int optind;

    while ((opt = getopt(argc, argv, "p:c")) != -1) {
        switch (opt) {
            case 'p':
                parallel_level = atoi(optarg);
                assert(parallel_level>0 && parallel_level<=256);
                break;
            case 'c':
                cheat = true;
                break;
        default: /* '?' */
            printf("Usage: %s -p parallel_level [-c]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("\nStart measurement for parallel level %d\n", parallel_level);

    char cheat_sufix[17];
    if(cheat)
    {
        sprintf(cheat_sufix, "cheating");
    }
    else
    {
       sprintf(cheat_sufix, "simulated-search");
    }

    double teoretical = 2.3123;
    if (CRYPTO_ALGNAME == "Kyber512")
    {
        printf("\nKyber512\n");
        teoretical = 2.5625;
    }
    char path[18];
    sprintf(path, "measurements/%s/", CRYPTO_ALGNAME);
    char filename[128];
    sprintf(filename, "%s%s_with_parallel_level_%03d_%s.txt",
                        path, CRYPTO_ALGNAME, parallel_level, cheat_sufix);
    // Open a file in writing mode
    FILE * datafile;
    datafile = fopen(filename, "w");
    if(datafile == NULL) {
        printf("\nError: the data-file could not be created\n");
        exit(EXIT_FAILURE);
    }
    //print file headers
    int header_size = 55;
    char block_header[header_size];
    sprintf(block_header,
        "\tb_index\tqueries\tcpu_time\tsearch_ops\tc_recov\tcoeff/q\t");

    char blocks_header_string[header_size*(KYBER_K+1)];
    sprintf(blocks_header_string ,"%s", block_header);
    //printf("blocks_header_string = %s\n", blocks_header_string);
    //printf("KYBER_K = %d\n", KYBER_K);
    for(int block_index = 1; block_index < KYBER_K; block_index++)
    {
        sprintf(blocks_header_string ,"%s%s", blocks_header_string, block_header);
    }
    //printf("blocks_header_string = %s\n", blocks_header_string);
    fprintf(datafile, "Seed\tF/P\t%s%s\n",
            blocks_header_string, "\tTotal:\tqueries\tcpu_time\tsearch_ops\tc_rec\tcoeffs/q(average)");
    // no totals headlines for now
    //    "Queries_Total\tTime_total\tOperations_Total\tCoeff_recovered_Total\tCoeff_per_queries_Total");
    unsigned long all_runs_sum_nbrof_queries_full = 0;
    unsigned long all_runs_sum_nbrof_queries_partial = 0;
    double all_runs_sum_cputime_full = 0;
    double all_runs_sum_cputime_part = 0;

    unsigned long all_runs_sum_nbrof_coeff_recovered_full = 0;
    unsigned long all_runs_sum_nbrof_coeff_recovered_partial = 0;

    unsigned long long all_runs_sum_nbrof_search_operations_full = 0;
    unsigned long long all_runs_sum_nbrof_search_operations_partial = 0;

    double all_runs_sum_coeff_per_queries_full = 0;
    double all_runs_sum_coeff_per_queries_partial = 0;


    uint8_t prints_verbosity;

    #define NBROF_RUNS 100

    for (int seed = 1; seed <= NBROF_RUNS; seed++)
    {
        single_run_measurement measurement;
        //init measurement
        measurement.seed = seed;
        for(uint8_t block_index = 0; block_index < KYBER_K; block_index ++)
        {
            measurement.blocks_partial_recovery[block_index].block_index = block_index;
            measurement.blocks_partial_recovery[block_index].nbrof_queries = 0;
            measurement.blocks_partial_recovery[block_index].cpu_time = 0;
            measurement.blocks_partial_recovery[block_index].nbrof_search_operations = 0;
            measurement.blocks_partial_recovery[block_index].nbrof_coeff_recovered = 0;
            measurement.blocks_full_recovery[block_index].block_index = block_index;
            measurement.blocks_full_recovery[block_index].nbrof_queries = 0;
            measurement.blocks_full_recovery[block_index].cpu_time = 0;
            measurement.blocks_full_recovery[block_index].nbrof_search_operations = 0;
            measurement.blocks_full_recovery[block_index].nbrof_coeff_recovered = 0;
        }

        printf("\nStarting new attack measurement, seed = %d\n", seed);
        adaptive_parallel_attack_with_measurements(seed, parallel_level, cheat, (prints_verbosity = 0), &measurement);


        for(uint8_t block_index = 0; block_index < KYBER_K; block_index ++)
        {
            measurement.blocks_partial_recovery[block_index].coeff_per_queries = 1.0 *
            measurement.blocks_partial_recovery[block_index].nbrof_coeff_recovered /
            measurement.blocks_partial_recovery[block_index].nbrof_queries ;
            measurement.blocks_full_recovery[block_index].coeff_per_queries = 1.0 *
            measurement.blocks_full_recovery[block_index].nbrof_coeff_recovered /
            measurement.blocks_full_recovery[block_index].nbrof_queries ;
        }
        measurement.blocks_partial_recovery_total.nbrof_queries = 0;
        measurement.blocks_partial_recovery_total.cpu_time = 0;
        measurement.blocks_partial_recovery_total.nbrof_search_operations = 0;
        measurement.blocks_partial_recovery_total.nbrof_coeff_recovered = 0;
        measurement.blocks_partial_recovery_total.coeff_per_queries = 0;
        measurement.blocks_full_recovery_total.nbrof_queries = 0;
        measurement.blocks_full_recovery_total.cpu_time = 0;
        measurement.blocks_full_recovery_total.nbrof_search_operations = 0;
        measurement.blocks_full_recovery_total.nbrof_coeff_recovered = 0;
        measurement.blocks_full_recovery_total.coeff_per_queries = 0;
        for(uint8_t block_index = 0; block_index < KYBER_K; block_index ++)
        {
            measurement.blocks_partial_recovery_total.nbrof_queries +=
                measurement.blocks_partial_recovery[block_index].nbrof_queries;
            measurement.blocks_partial_recovery_total.cpu_time +=
                measurement.blocks_partial_recovery[block_index].cpu_time;
            measurement.blocks_partial_recovery_total.nbrof_search_operations +=
                measurement.blocks_partial_recovery[block_index].nbrof_search_operations;
            measurement.blocks_partial_recovery_total.nbrof_coeff_recovered +=
                measurement.blocks_partial_recovery[block_index].nbrof_coeff_recovered;
            //measurement.blocks_partial_recovery_total.coeff_per_queries +=
            //    measurement.blocks_partial_recovery[block_index].coeff_per_queries;

            measurement.blocks_full_recovery_total.nbrof_queries +=
                measurement.blocks_full_recovery[block_index].nbrof_queries;
            measurement.blocks_full_recovery_total.cpu_time +=
                measurement.blocks_full_recovery[block_index].cpu_time;
            measurement.blocks_full_recovery_total.nbrof_search_operations +=
                measurement.blocks_full_recovery[block_index].nbrof_search_operations;
            measurement.blocks_full_recovery_total.nbrof_coeff_recovered +=
                measurement.blocks_full_recovery[block_index].nbrof_coeff_recovered;
            //measurement.blocks_full_recovery_total.coeff_per_queries +=
            //    measurement.blocks_full_recovery[block_index].coeff_per_queries;
        }
        // calc single-run averages
        //measurement.blocks_partial_recovery_total.coeff_per_queries /= KYBER_K;
        //measurement.blocks_full_recovery_total.coeff_per_queries /= KYBER_K;
         measurement.blocks_partial_recovery_total.coeff_per_queries = 1.0 *
            measurement.blocks_partial_recovery_total.nbrof_coeff_recovered /
            measurement.blocks_partial_recovery_total.nbrof_queries ;
        measurement.blocks_full_recovery_total.coeff_per_queries = 1.0 *
            measurement.blocks_full_recovery_total.nbrof_coeff_recovered /
            measurement.blocks_full_recovery_total.nbrof_queries ;
        // Write result to textfile
        printf("\nwriting measurements to data-file\n");
        print_measurement_to_file(datafile, &measurement);
        //accumulate the sums for all runs
        all_runs_sum_nbrof_queries_full              += measurement.blocks_full_recovery_total.nbrof_queries;
        all_runs_sum_nbrof_queries_partial           += measurement.blocks_partial_recovery_total.nbrof_queries;

        all_runs_sum_cputime_full                    += measurement.blocks_full_recovery_total.cpu_time;
        all_runs_sum_cputime_part                    += measurement.blocks_partial_recovery_total.cpu_time;
        all_runs_sum_nbrof_coeff_recovered_full      += measurement.blocks_full_recovery_total.nbrof_coeff_recovered;
        all_runs_sum_nbrof_coeff_recovered_partial   += measurement.blocks_partial_recovery_total.nbrof_coeff_recovered;
        all_runs_sum_nbrof_search_operations_full    += measurement.blocks_full_recovery_total.nbrof_search_operations;
        all_runs_sum_nbrof_search_operations_partial += measurement.blocks_partial_recovery_total.nbrof_search_operations;
        all_runs_sum_coeff_per_queries_full          += measurement.blocks_full_recovery_total.coeff_per_queries;
        all_runs_sum_coeff_per_queries_partial       += measurement.blocks_partial_recovery_total.coeff_per_queries;
    }
    // Close the file
    fclose(datafile);
    printf("writing averages to average-files\n");
    //calculate averages
    //averages for full
    //uint16_t average_nbrof_queries =
    //output to file
    write_averages(path, "full", parallel_level,
                   (double) all_runs_sum_nbrof_queries_full / NBROF_RUNS,
                   all_runs_sum_cputime_full / NBROF_RUNS,//double average_cpu_time
                   (double) all_runs_sum_nbrof_search_operations_full / NBROF_RUNS,//average_nbrof_search_operations
                   (double) all_runs_sum_nbrof_coeff_recovered_full / NBROF_RUNS,//double average_nbrof_coeff_recovered,
                   all_runs_sum_coeff_per_queries_full / NBROF_RUNS,//double average_coeff_per_query
                 teoretical
                 );
    //averages for partial
    //output to file
    write_averages(path, "partial", parallel_level,
                   (double) all_runs_sum_nbrof_queries_partial / NBROF_RUNS,
                   all_runs_sum_cputime_part / NBROF_RUNS,//double average_cpu_time,
                   (double) all_runs_sum_nbrof_search_operations_partial / NBROF_RUNS,//average_nbrof_search_operations
                   (double) all_runs_sum_nbrof_coeff_recovered_partial / NBROF_RUNS,//double average_nbrof_coeff_recovered,
                   all_runs_sum_coeff_per_queries_partial / NBROF_RUNS,//double average_coeff_per_query
                   teoretical);


    printf("\n...done measuring.\n");


    exit(EXIT_SUCCESS);
}
