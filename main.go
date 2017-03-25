package main

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strconv"
	"time"
)

var text = `type=DAEMON_START msg=audit(1490386608.912:5918): auditd start, ver=2.4 format=raw kernel=3.16.0-4-amd64 auid=4294967295 pid=1802 res=success
type=SERVICE_START msg=audit(1490386608.916:4): pid=1 uid=0 auid=4294967295 ses=4294967295 msg=' comm="auditd" exe="/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
type=USER_END msg=audit(1490386609.336:5): pid=1282 uid=0 auid=1000 ses=3 msg='op=PAM:session_close acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=CRED_DISP msg=audit(1490386609.336:6): pid=1282 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_CMD msg=audit(1490386609.336:7): pid=1832 uid=1000 auid=1000 ses=3 msg='cwd="/vagrant" cmd=736572766963652061756469746420737461747573 terminal=pts/0 res=success'
type=CRED_REFR msg=audit(1490386609.336:8): pid=1832 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_START msg=audit(1490386609.340:9): pid=1832 uid=0 auid=1000 ses=3 msg='op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_END msg=audit(1490386609.364:10): pid=1832 uid=0 auid=1000 ses=3 msg='op=PAM:session_close acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=CRED_DISP msg=audit(1490386609.364:11): pid=1832 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_ACCT msg=audit(1490386621.064:12): pid=1836 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=CRED_ACQ msg=audit(1490386621.064:13): pid=1836 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:setcred acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=LOGIN msg=audit(1490386621.064:14): pid=1836 uid=0 old-auid=4294967295 auid=0 old-ses=4294967295 ses=4 res=1
type=USER_START msg=audit(1490386621.064:15): pid=1836 uid=0 auid=0 ses=4 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=CRED_DISP msg=audit(1490386621.064:16): pid=1836 uid=0 auid=0 ses=4 msg='op=PAM:setcred acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=USER_END msg=audit(1490386621.068:17): pid=1836 uid=0 auid=0 ses=4 msg='op=PAM:session_close acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=USER_CMD msg=audit(1490386677.796:18): pid=1886 uid=1000 auid=1000 ses=3 msg='cwd="/vagrant" cmd="-bash" terminal=pts/0 res=success'
type=CRED_REFR msg=audit(1490386677.796:19): pid=1886 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_START msg=audit(1490386677.796:20): pid=1886 uid=0 auid=1000 ses=3 msg='op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=CONFIG_CHANGE msg=audit(1490386710.648:21): auid=1000 ses=3 op="add rule" key="network_outbound" list=4 res=1
type=SYSCALL msg=audit(1490386723.364:22): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec4ee47bf4 a2=10 a3=7ffdadee5ef0 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.364:22): saddr=020000350A0002030000000000000000
type=PROCTITLE msg=audit(1490386723.364:22): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:23): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec507f3a00 a2=10 a3=0 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:23): saddr=020000500599E7040000000000000000
type=PROCTITLE msg=audit(1490386723.396:23): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:24): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:24): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:24): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:25): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec507f3a50 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:25): saddr=020000509514040F0000000000000000
type=PROCTITLE msg=audit(1490386723.396:25): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:26): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:26): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:26): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:27): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec50806d20 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:27): saddr=020000508CD3A6CA0000000000000000
type=PROCTITLE msg=audit(1490386723.396:27): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:28): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:28): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:28): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:29): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec50806d70 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:29): saddr=020000508259940E0000000000000000
type=PROCTITLE msg=audit(1490386723.396:29): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:30): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:30): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:30): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:31): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fec50806dc0 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:31): saddr=02000050801F003E0000000000000000
type=PROCTITLE msg=audit(1490386723.396:31): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:32): arch=c000003e syscall=42 success=no exit=-101 a0=3 a1=7fec50806e10 a2=1c a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:32): saddr=0A000050 0000 0000 2001 0610 1908 B000 0000 0000 0148 0014 0000 0000
type=PROCTITLE msg=audit(1490386723.396:32): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:33): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:33): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:33): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:34): arch=c000003e syscall=42 success=no exit=-101 a0=3 a1=7fec50806e70 a2=1c a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:34): saddr=0A000050000000002605BC8030100B0000000DEB0166020200000000
type=PROCTITLE msg=audit(1490386723.396:34): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:35): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:35): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:35): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:36): arch=c000003e syscall=42 success=no exit=-101 a0=3 a1=7fec50806ed0 a2=1c a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:36): saddr=0A00005000000000200141C810000021000000000021000400000000
type=PROCTITLE msg=audit(1490386723.396:36): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:37): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffdadee8020 a2=10 a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:37): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386723.396:37): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:38): arch=c000003e syscall=42 success=no exit=-101 a0=3 a1=7fec50806f30 a2=1c a3=10 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:38): saddr=0A00005000000000200104F80001000C000000000000001500000000
type=PROCTITLE msg=audit(1490386723.396:38): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.396:39): arch=c000003e syscall=42 success=no exit=-115 a0=3 a1=7fec507f3a00 a2=10 a3=7ffdadee7ea0 items=0 ppid=1898 pid=1903 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.396:39): saddr=020000500599E7040000000000000000
type=PROCTITLE msg=audit(1490386723.396:39): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.444:40): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fe926618bf4 a2=10 a3=7ffee9374cf0 items=0 ppid=1898 pid=1904 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.444:40): saddr=020000350A0002030000000000000000
type=PROCTITLE msg=audit(1490386723.444:40): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.464:41): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fe928707a10 a2=10 a3=0 items=0 ppid=1898 pid=1904 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.464:41): saddr=02000050976510CC0000000000000000
type=PROCTITLE msg=audit(1490386723.464:41): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.464:42): arch=c000003e syscall=42 success=no exit=-101 a0=3 a1=7fe928707a60 a2=1c a3=10 items=0 ppid=1898 pid=1904 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.464:42): saddr=0A000050000000002A044E4200040000000000000000020400000000
type=PROCTITLE msg=audit(1490386723.464:42): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386723.464:43): arch=c000003e syscall=42 success=no exit=-115 a0=3 a1=7fe928707a10 a2=10 a3=7ffee9376ca0 items=0 ppid=1898 pid=1904 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="http" exe="/usr/lib/apt/methods/http" key="network_outbound"
type=SOCKADDR msg=audit(1490386723.464:43): saddr=02000050976510CC0000000000000000
type=PROCTITLE msg=audit(1490386723.464:43): proctitle="/usr/lib/apt/methods/http"
type=SYSCALL msg=audit(1490386726.536:44): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826586dcc a2=10 a3=7f1826583c60 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.536:44): saddr=020000350A0002030000000000000000
type=PROCTITLE msg=audit(1490386726.536:44): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.568:45): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001c30 a2=10 a3=0 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.568:45): saddr=02000050D155CA630000000000000000
type=PROCTITLE msg=audit(1490386726.568:45): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.568:46): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826585d90 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.568:46): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386726.568:46): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:47): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001c80 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:47): saddr=02000050D155CA670000000000000000
type=PROCTITLE msg=audit(1490386726.572:47): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:48): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826585d90 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:48): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386726.572:48): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:49): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001cd0 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:49): saddr=02000050D155CA690000000000000000
type=PROCTITLE msg=audit(1490386726.572:49): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:50): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826585d90 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:50): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386726.572:50): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:51): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001d20 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:51): saddr=02000050D155CA6A0000000000000000
type=PROCTITLE msg=audit(1490386726.572:51): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:52): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826585d90 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:52): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386726.572:52): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:53): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001d70 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:53): saddr=02000050D155CA680000000000000000
type=PROCTITLE msg=audit(1490386726.572:53): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:54): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1826585d90 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:54): saddr=00000000000000000000000000000000
type=PROCTITLE msg=audit(1490386726.572:54): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:55): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7f1820001dc0 a2=10 a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:55): saddr=02000050D155CA930000000000000000
type=PROCTITLE msg=audit(1490386726.572:55): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.572:56): arch=c000003e syscall=42 success=no exit=-101 a0=4 a1=7f1820001e10 a2=1c a3=10 items=0 ppid=1887 pid=2143 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.572:56): saddr=0A000050000000002A001450400B0801000000000000200400000000
type=PROCTITLE msg=audit(1490386726.572:56): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
type=SYSCALL msg=audit(1490386726.600:57): arch=c000003e syscall=42 success=no exit=-115 a0=4 a1=7ffc449b4180 a2=10 a3=27e items=0 ppid=1887 pid=2142 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="network_outbound"
type=SOCKADDR msg=audit(1490386726.600:57): saddr=02000050D155CA630000000000000000
type=PROCTITLE msg=audit(1490386726.600:57): proctitle=6375726C002D7600687474703A2F2F7777772E676F6F676C652E636F6D
`

func main() {

	var results []map[string]string

	re, err := regexp.Compile(`(?im)type=SYSCALL msg=audit\((?P<epoch>\d+.\d+):\d+\): arch=\w+ syscall=\d+ success=(?P<success>\w+) exit=?(?P<exit>\-?\d+) \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ \w+=\d+ ppid=(?P<ppid>\d+) pid=(?P<pid>\d+) \w+=\w+ uid=(?P<uid>\d+) gid=(?P<gid>\d+) \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ \w+=\w+ comm=\"(?P<comm>\w+)\" exe=\"(?P<exe>[\w\/]+)" key=\"(?P<key>\w+)\"\ntype=SOCKADDR msg=audit\(\d+.\d+:\d+\): saddr=(?P<saddr>\w+)\ntype=PROCTITLE msg=audit\(\d+.\d+:\d+\): .*$`)
	if err != nil {
		fmt.Printf("There was an error. %v\n", err)
	}

	n1 := re.SubexpNames()
	result := re.FindAllStringSubmatch(text, -1)
	fmt.Println(n1)
	for _, v := range result {
		md := map[string]string{}
		for k, v := range v {
			if n1[k] == "epoch" {
				i, _ := strconv.ParseFloat(v, 64)
				md["timestamp"] = fmt.Sprintf("%v", time.Unix(int64(i), 0))
			}
			if n1[k] == "saddr" {
				// this is where we conver the saddr string to IPv4/6 type, Port, IP address
				// convert a string extracted to hex then from hex to int
				s1 := v[:2]
				s2 := v[2:8]
				s3 := v[8:16]
				md["ip_raw"] = v[8:]

				i1, _ := strconv.ParseInt(s1, 16, 0)
				i2, _ := strconv.ParseInt(s2, 16, 0)

				if i1 == 2 {
					md["iptype"] = "ipv4"
				}
				if i1 == 10 {
					md["iptype"] = "ipv6"
				}

				md["port"] = strconv.Itoa(int(i2))

				// convert hex to slice of string
				i3, _ := hex.DecodeString(s3)
				md["ip"] = fmt.Sprintf("%v.%v.%v.%v", i3[0], i3[1], i3[2], i3[3])

				if i1 == 10 {
					ipv6 := v[16 : len(v)-8]
					_ipv6 := make([]string, 0)

					for i := 0; i < len(ipv6); i += 4 {
						_ipPart := fmt.Sprintf("%v", ipv6[i:i+4])
						_ipv6 = append(_ipv6, _ipPart)
					}
					md["ipv6"] = fmt.Sprintf("%v:%v:%v:%v:%v:%v:%v:%v", _ipv6[0], _ipv6[1], _ipv6[2], _ipv6[3], _ipv6[4], _ipv6[5], _ipv6[6], _ipv6[7])
				}
			}
			md[n1[k]] = v
		}
		delete(md, "")
		results = append(results, md)
	}

	t := template.Must(template.New("t1").Parse("{{.timestamp | html}} prog={{.exe}} uid={{.uid}} gid={{.gid}} pid={{.ppid}}:{{.pid}} exit={{.exit}} key={{.key}} type={{.iptype}} addr={{ if .ipv6 }}{{.ipv6}}{{ else }}{{.ip}}{{ end }} port={{.port}}\n"))

	for _, val := range results {
		t.Execute(os.Stdout, val)
	}

}
