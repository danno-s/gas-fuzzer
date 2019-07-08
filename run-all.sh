echo "" > exec.log

echo "starting..."

for file in etherscan/*
do
    python3 gas_fuzz/gas_fuzz.py -tx 15 -s 10 $file >> /dev/null
    if [ $? -ne 0 ]
    then
        echo "failure on $file" >> exec.log
    fi
done

echo "finished!"