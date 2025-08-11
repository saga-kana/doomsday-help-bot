ps -ef | grep capture.py | grep -v sudo  | grep -v grep | awk '{print $(NF-3)}' | while read i; 
do 
	sudo tcpdump -c 1 -i enp1s0 src port $i -l 2> /dev/null | awk -F '[: ]+' '{printf "%d %s\n", -($1*3600+$2*60+$3)*1000 + $(NF-4), $9}' ; 
done

echo

while read -r i; do
  {
    timeout 16s nohup sudo tcpdump -c 1 -i enp1s0 src port "$i" -l 2>/dev/null |
      awk -F '[: ]+' '{printf "%d %s\n", -($1*3600+$2*60+$3)*1000 + $(NF-4), $9}' 2>/dev/null ||
      echo "timeout $i"
  } &
done < <(ps -ef | grep capture.py | grep -v sudo | grep -v grep | awk '{print $(NF-1)}')

wait
echo end

