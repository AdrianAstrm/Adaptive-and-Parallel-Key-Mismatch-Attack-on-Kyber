# Attribution

This repository contains a demostration of the adaptive and parallel key mismatch attack on Kyber, presented by Guo, Mårtensson and Åström in the article:

**"The Perils of Limited Key Reuse: Adaptive and Parallel Mismatch Attacks with Post-processing Against Kyber"**  
(to be uploaded to ePrint)  

The attack builds on an attack by Qin et al., presented in: 

**"A Systematic Approach and Analysis of Key
Mismatch Attacks on Lattice-Based NIST
Candidate KEMs"**  
Avaliable at: 
https://link.springer.com/chapter/10.1007/978-3-030-92068-5_4

This repositrory is a fork of the implementations of the attacks in the article above, to credit the authors of the original attack. Only the attack on Kyber is used.
<!---
https://github.com/AHaQY/Key-Mismatch-Attack-on-NIST-KEMs
-->

# Dependencies

The pseudorandomness for generating key-pairs uses AES from the openSSL library. Therefore you need to have the openSSL development tools installed on your system.

On a debian-based linux distribution you can install it with **apt**:
> sudo apt install libssl-dev

The attack has only been tested on Linux, but it should be possible to build it on other OSes as well.

In the script **measure_attack.sh**, the linux-specific **chrt** is used to set the process scheduling to **SCHED_BATCH**. It can however be omitted without breaking the script or measurements.


#
# Build

To build, test and run, first cd to the directory:

> cd adaptive_parallel_key_mismatch_attack

You can use make to build the attack demo:

> make

There are 3 targets that can be built separately.

> make run  
> make test  
> make measure

#
# Run

To run the attack with desired parameters, issue any of the commands:

>  ./run/attack_kyber512 -p p_level -s seed -v verbosity_level [-c]  
>  ./run/attack_kyber768 -p p_level -s seed -v verbosity_level [-c]  
>  ./run/attack_kyber1024 -p p_level -s seed -v verbosity_level [-c]

where 
- **p_level**  - an integer from 1 to 256, is the parallelization level of the attack, 
- **seed**  - an integer, the seed for pseudorandomness when generating key-pairs,
- **verbosity_level** -  an integer from 0 to 4, controlling the amount of prints to the terminal.
- **-c** -  an option to turn on 'cheating' when searching for the correct m-array.
 
If mode is not set to cheating, the maximum supported p_level is 63.

Example:

> ./run/attack_kyber1024 -p 15 -s 123 -v 2  
<!---
> Attacking Kyber1024...
-->
<!---
A remark on parallization level and execution time
-->
For larger parallization levels (>15), the attack will take a while to complete if you are not using the cheating option. With p_level > 45, the simulation is expected to take years to complete. This is due to the exponential time complexity of the offline plaintext checking oracle (searching for the correct m-array). 

Verbosity level can also affect execution time.

#
# Test

Binaries for running tests can be built:

> make tests

The tests can be run individually with any of:

> ./test/test_kyber512  
> ./test/test_kyber768  
> ./test/test_kyber1024

There is also a shell sqript for automating all the above:

> ./make_and_test.sh


#
# Measurements of the simulated attack

Binaries for measuring the performance of the attack can be built.

> make measure

You can run all of them, and for all parallelization levels using the shellscript:

> ./measure_attacks.sh

You can also run a measurement of a simulated attack on a single security level, using a fix parallelization level.
First you need to cd to the measure directory.

> cd measure

Here you can issue any of the commands below.

> ./measure_attack_kyber512 -p p_level [-c]
> ./measure_attack_kyber768 -p p_level [-c]
> ./measure_attack_kyber1024 -p p_level [-c]

where 
- **p_level**  - is the parallelization level of the attack, 
- **-c** -  an option to turn on 'cheating' when searching for the m-array.

### The following will be measured for each block:

- **queries** - the number of queries used to recover the block.
- **cpu_time** - the cpu-time spent recovering the block.
- **search_ops** - the total number of search operations performed to recover the block.
- **c_recov** - number of coefficients recovered.
- **coeff/q** - average number of coefficients recovered per query.

The programs will write the measurements of 100 attacks to a file. Both full and partial recovery of the secret key will be included. Averages of the 100 measurements will be appended to two average-files.

Measurements files example:
> /measure/measurements/Kyber1024/  
> Kyber1024_averages_full.txt  
> Kyber1024_averages_partial.txt  
> Kyber1024_with_parallel_level_001_simulated-search.txt  
> ...    
> Kyber1024_with_parallel_level_256_cheating.txt  


#
# Development

Near future updates include:

- Applying the attack extensions to an updated version of Kyber.
- Implementing a more realistic simulation of an oracle, where a key is derived and a message is decrypted unsing AES.

