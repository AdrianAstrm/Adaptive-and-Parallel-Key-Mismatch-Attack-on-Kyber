touch test_attack.c


make test_attack_kyber512  && ./test/test_attack_kyber512
make test_attack_kyber768  && ./test/test_attack_kyber768
make test_attack_kyber1024 && ./test/test_attack_kyber1024


echo "Attacks for all security levels built and tested."
echo
