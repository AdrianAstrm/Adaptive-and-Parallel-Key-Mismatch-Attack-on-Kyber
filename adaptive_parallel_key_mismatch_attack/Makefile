CC=/usr/bin/gcc
K3AE_PATH=../kyber_NIST_round3_with_attack_extensions/
CFLAGS += -march=native -fomit-frame-pointer -O3 -I$(K3AE_PATH)
LDFLAGS=-lcrypto -O3

SOURCES= adaptive_parallel_singlethread.c \
		 $(K3AE_PATH)cbd.c \
		 $(K3AE_PATH)fips202.c \
		 $(K3AE_PATH)indcpa.c \
		 $(K3AE_PATH)ntt.c \
		 $(K3AE_PATH)kem.c \
		 $(K3AE_PATH)poly.c \
		 $(K3AE_PATH)polyvec.c \
		 $(K3AE_PATH)reduce.c \
		 $(K3AE_PATH)rng.c \
		 $(K3AE_PATH)verify.c \
		 $(K3AE_PATH)symmetric-shake.c

HEADERS= adaptive_parallel_singlethread.h \
		 $(K3AE_PATH)api.h \
		 $(K3AE_PATH)cbd.h \
		 $(K3AE_PATH)fips202.h \
		 $(K3AE_PATH)indcpa.h \
		 $(K3AE_PATH)ntt.h \
		 $(K3AE_PATH)kem.h \
		 $(K3AE_PATH)params.h \
		 $(K3AE_PATH)poly.h \
		 $(K3AE_PATH)polyvec.h \
		 $(K3AE_PATH)reduce.h \
		 $(K3AE_PATH)rng.h \
		 $(K3AE_PATH)verify.h \
		 $(K3AE_PATH)symmetric.h


all:	run test measure

run:     attack_kyber512 \
		 attack_kyber768 \
		 attack_kyber1024

test:    test_attack_kyber512 \
		 test_attack_kyber768 \
		 test_attack_kyber1024

measure: measure_attack_kyber512 \
		 measure_attack_kyber768 \
		 measure_attack_kyber1024


create_dir_run:
	    mkdir -p run
create_dir_test:
	    mkdir -p test

attack_kyber512: $(HEADERS) $(SOURCES) BRT_kyber512.c run_attack.c | create_dir_run
	$(CC) $(CFLAGS) -DKYBER_K=2 -o run/$@ $(SOURCES) run_attack.c BRT_kyber512.c $(LDFLAGS)

attack_kyber768: $(HEADERS) $(SOURCES) BRT_kyber768.c run_attack.c | create_dir_run
	$(CC) $(CFLAGS) -DKYBER_K=3 -o run/$@ $(SOURCES) BRT_kyber768.c run_attack.c $(LDFLAGS)

attack_kyber1024: $(HEADERS) $(SOURCES) BRT_kyber1024.c run_attack.c | create_dir_run
	$(CC) $(CFLAGS) -DKYBER_K=4 -o run/$@ $(SOURCES) BRT_kyber1024.c run_attack.c $(LDFLAGS)


test_attack_kyber512: $(HEADERS) $(SOURCES) BRT_kyber512.c test_attack.c | create_dir_test
	$(CC) $(CFLAGS) -DKYBER_K=2 -o test/$@ $(SOURCES) BRT_kyber512.c test_attack.c $(LDFLAGS)

test_attack_kyber768: $(HEADERS) $(SOURCES) BRT_kyber768.c test_attack.c | create_dir_test
	$(CC) $(CFLAGS) -DKYBER_K=3 -o test/$@ $(SOURCES) BRT_kyber768.c test_attack.c $(LDFLAGS)

test_attack_kyber1024: $(HEADERS) $(SOURCES) BRT_kyber1024.c test_attack.c | create_dir_test
	$(CC) $(CFLAGS) -DKYBER_K=4 -o test/$@ $(SOURCES) BRT_kyber1024.c test_attack.c $(LDFLAGS)


measure_attack_kyber512: $(HEADERS) $(SOURCES) BRT_kyber512.c measure_attack.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -o measure/$@ $(SOURCES) BRT_kyber512.c measure_attack.c $(LDFLAGS)

measure_attack_kyber768: $(HEADERS) $(SOURCES) BRT_kyber768.c measure_attack.c
	$(CC) $(CFLAGS) -DKYBER_K=3 -o measure/$@ $(SOURCES) BRT_kyber768.c measure_attack.c $(LDFLAGS)

measure_attack_kyber1024: $(HEADERS) $(SOURCES) BRT_kyber1024.c measure_attack.c
	$(CC) $(CFLAGS) -DKYBER_K=4 -o measure/$@ $(SOURCES) BRT_kyber1024.c measure_attack.c $(LDFLAGS)

.PHONY: clean

clean:
	-rm run/attack_kyber512
	-rm run/attack_kyber768
	-rm run/attack_kyber1024
	-rm test/test_attack_kyber512
	-rm test/test_attack_kyber768
	-rm test/test_attack_kyber1024
	-rm measure/measure_attack_kyber512
	-rm measure/measure_attack_kyber768
	-rm measure/measure_attack_kyber1024

