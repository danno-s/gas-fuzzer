echo "" > exec.log

for file in /home/HDD/Dropbox/Dropbox/ContractsDB/etherscan/*
do
    python3 gas_fuzz/gas_fuzz.py -n 5 -tx 5 $file
    if [ $? -ne 0 ]
    then
        echo "failure on $file" >> exec.log
    fi
done
