kill -9 $(netstat -alnp | grep 1234 | awk -F " " '{print $NF}'  | cut -d "/" -f 1)
