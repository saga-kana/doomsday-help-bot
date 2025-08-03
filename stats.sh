for i in $(ls /tmp/capture*.log | grep -v _all); 
do 
    count=$(grep -a HELP "$i" | wc -l) ; 
    
    result=$(tail -2 "$i" | strings | grep -a HELP -A 1 | tr -d "\n" | sed -e "s/\\[[0-9\.]*\\]//g" -e "s/-//g" -e "s/://g"; )
    echo $result | grep -E "ACK RECV|ACK received" > /dev/null
    if [ $? -eq 0 ]; then
        result="ACK RECV"
    else
        result="ACK NOT RECV"
    fi
    # echo "### $i $count $result" ;
    printf "### %-20s %5d  %-12s\n" "$i" "$count" "$result"
    # echo "--------------------" ;
    # echo ; 
done ; 
echo ; 

# cat /tmp/help.log | awk "{print \$(NF-1),\$(NF)}" | sed -e "s/:.*:.*//" | uniq -c | tail -7