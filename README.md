# A small Go program to read /var/log/audit/audit.log

Ever wondered where your host is trying to connect to ? Enable auditing of outogoing connections and use this tool to get a simple list of outgoing connections detailing the date/time the application, parent pid and pid, the user and group id and the destination IP:PORT.

### Pre-req

- you must have auditd installed

### Enable the auditing

Monitoring syscalls can be expensive, try to limit the number of rules to a minimum by applying filters, the one below works, but may need some optimisation for your system.

```
# auditctl -a exit,always -F arch=b64 -S connect -F a2!=110 -k network_outbound
```

### Do some curls

```
curl -v -g -6 "https://[2a00:1450:4009:80d::200e]/" 1>/dev/null
curl -v https://www.google.com 1>/dev/null
```

### Example log

```
type=SYSCALL msg=audit(1531903575.684:1152): arch=c000003e syscall=42 success=no exit=-115 a0=3 a1=7ffc57d16b70 a2=10 a3=7ffc57d16460 items=0 ppid=2076 pid=6422 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=31 comm="curl" exe="/usr/bin/curl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="network_outbound"
type=SOCKADDR msg=audit(1531903575.684:1152): saddr=020001BBD83AD5440000000000000000
type=PROCTITLE msg=audit(1531903575.684:1152): proctitle=6375726C002D760068747470733A2F2F7777772E676F6F676C652E636F6D
```

### Run auditr

**run**
```
go run main.go -f /var/log/audit/audit.log
```

**install & run**
```
go get github.com/alex-leonhardt/auditr
(${GOPATH}/bin/)auditr -f /path/to/audit.log
```

**get help**
```
$GOPATH/bin/auditr -h
```

### Example Output

```
2018-07-18 09:40:25 +0000 UTC prog=/usr/bin/curl uid=0 gid=0 pid=2076:9471 exit=-101 key=network_outbound type=ipv6 addr=2A00:1450:4009:080D:0000:0000:0000:200E port=443
2018-07-18 09:40:28 +0000 UTC prog=/usr/bin/curl uid=0 gid=0 pid=2076:9475 exit=0 key=network_outbound type=ipv4 addr=10.0.2.3 port=53
2018-07-18 09:40:28 +0000 UTC prog=/usr/bin/curl uid=0 gid=0 pid=2076:9475 exit=0 key=network_outbound type=ipv4 addr=216.58.198.228 port=443
2018-07-18 09:40:28 +0000 UTC prog=/usr/bin/curl uid=0 gid=0 pid=2076:9475 exit=-101 key=network_outbound type=ipv6 addr=2A00:1450:4009:0811:0000:0000:0000:2004 port=443
2018-07-18 09:40:28 +0000 UTC prog=/usr/bin/curl uid=0 gid=0 pid=2076:9475 exit=-115 key=network_outbound type=ipv4 addr=216.58.198.228 port=443
```
