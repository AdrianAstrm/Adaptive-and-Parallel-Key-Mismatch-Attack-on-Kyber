touch measure_attack.c && make measure

cd measure

cheating_theashold=10

for ((i = 1 ; i < $cheating_theashold ; i++)); do
     chrt -b 0 ./measure_attack_kyber512 -p $i
     chrt -b 0 ./measure_attack_kyber768 -p $i
     chrt -b 0 ./measure_attack_kyber1024 -p $i
done

for ((i = $cheating_theashold ; i <= 256 ; i++)); do
     chrt -b 0 ./measure_attack_kyber512 -p $i -c
     chrt -b 0 ./measure_attack_kyber768 -p $i -c
     chrt -b 0 ./measure_attack_kyber1024 -p $i -c
done

echo "Attacks on all security levels built and measured."
echo
