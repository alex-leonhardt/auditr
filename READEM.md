# A small Go program to read /var/log/audit/audit.log

Enable auditing of outogoing connections

### Pre-req
- you must have auditd installed

### Enable the auditing
```
# auditctl -a exit,always -F arch=b64 -S connect -F a2!=110 -k network_outbound
```

### Do some curls
```
curl -v http://www.google.com
```

### Run auditr
*(Note: this is still in progress, currently only takes inline text)*
```
go run main.go -f /var/log/audit/audit.log
```

### Example Output
```
2017-03-24 20:18:43 +0000 GMT prog=/usr/lib/apt/methods/http uid=0 gid=0 pid=1898:1904 exit=-115 key=network_outbound type=ipv4 addr=151.101.16.204 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=10.0.2.3 port=53
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.99 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type= addr=0.0.0.0 port=0
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.103 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type= addr=0.0.0.0 port=0
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.105 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type= addr=0.0.0.0 port=0
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.106 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type= addr=0.0.0.0 port=0
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.104 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type= addr=0.0.0.0 port=0
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=0 key=network_outbound type=ipv4 addr=209.85.202.147 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2143 exit=-101 key=network_outbound type=ipv6 addr=2A00:1450:400B:0801:0000:0000:0000:2004 port=80
2017-03-24 20:18:46 +0000 GMT prog=/usr/bin/curl uid=0 gid=0 pid=1887:2142 exit=-115 key=network_outbound type=ipv4 addr=209.85.202.99 port=80
```
