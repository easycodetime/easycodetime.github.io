# 根据pid知道可执行文件路径
```readlink -f /proc/pid/exe```

# 遍历所有进程的可执行文件路径
```for pid in $(ls /proc | grep -E '^[0-9]+$'); do exe=$(readlink -f /proc/$pid/exe 2>/dev/null) && echo "$pid $exe"; done```

# find搜索
```
find / -type f -name "*.so" | grep -i "log" | xargs -n1 -I{} sh -c 'strings "{}" | grep "搜索字符串" && echo "find in: {}" && echo'
find / -type f -name "*.so" | grep -i "log" | xargs -n1 -I{} sh -c 'readelf -s "{}" | grep "搜索字符串" && echo "find in: {}" && echo'
```

# strace常用记录
```
strace -xx -f -o xxx.log -e trace=network,write,read -p pid     以16进制形式来记录
strace -s 2048 -f -o xxx.log -e trace=network,write,read -p pid  以字符串形式来记录
```

