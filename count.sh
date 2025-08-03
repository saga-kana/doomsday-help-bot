#!/bin/bash

file="/tmp/help.log"

# データの整形と集計
awk '{print $(NF-1), $(NF)}' "$file" | sed 's/:.*:.*//' | sort | uniq -c |
awk '{
    count = $1
    date = $2
    hour = $3
    data[date,hour] = count
    dates[date] = 1
    hours[hour] = 1
}
END {
    # 時刻（列ヘッダ）を昇順で出す
    split("", hour_list)
    for (h in hours) hour_list[h] = h
    n = asorti(hour_list, sorted_hours)

    # 日付（行ヘッダ）も昇順で出す
    split("", date_list)
    for (d in dates) date_list[d] = d
    m = asorti(date_list, sorted_dates)

    # ヘッダー出力（時刻横並び）
    printf "%-12s", "date"
    for (i = 1; i <= n; i++) printf "%5s", sorted_hours[i]
    print ""

    # 各日付ごとに行を出力（昇順）
    for (j = 1; j <= m; j++) {
        d = sorted_dates[j]
        printf "%-12s", d
        for (i = 1; i <= n; i++) {
            h = sorted_hours[i]
            key = d SUBSEP h
            printf "%5d", (key in data) ? data[key] : 0
        }
        print ""
    }
}'

