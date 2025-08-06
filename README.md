# 再接続を止める
```
sudo iptables -I FORWARD -p tcp -d 204.141.172.10 --tcp-flags SYN SYN -j DROP
```
# capture
```
sudo venv/bin/python capture.py 38884 11530 34848 11539
```
# port list
```
sudo tcpdump -i waydroid0 -n -tt -l dst host 204.141.172.10 | awk  'BEGIN {   
    # 除外リストを読み込む   
    while ((getline < "exclude.txt") > 0) {     
        exclude[$0] = 1;   
        } 
    } 
    /IP/ {   
        proto = ($2 ~ /UDP/) ? "UDP" : "TCP";   
        split($3, src, /\./);   
        split($5, dst, /\./);   
        gsub(":", "", dst[5]);   
        sip = src[1]"."src[2]"."src[3]"."src[4];   
        dip = dst[1]"."dst[2]"."dst[3]"."dst[4];   
        sport = src[5];   
        dport = dst[5];   
        line = sport " " dport;    
        if (!exclude[line] && !seen[line]++) {     
            print line;     
            fflush();   
        } 
    }'
```
# HELP.txt
```
sudo tcpdump -i waydroid0 -n -tt -l dst host 204.141.172.10 -X | TZ=Asia/Tokyo  awk  '/0x[0-9a-f]+:/ {
    for (i = 2; i <= NF; i++) {
        hex = hex $i;
    }
}
/length/ {
    if (hex ~ /0400e228/ ) {
        system("touch help.txt");
        print "match found: 0400e228 → help.txt 作成済み",strftime("%Y-%m-%d %H:%M:%S")
    }
    hex = "";
}'
```

# ログ出力
```
tmux pipe-pane -t manage:0 "cat >> /tmp/help.log"
```


