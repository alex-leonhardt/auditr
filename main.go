// A small app to parse audit.log files and output a list of outgoing connections
// Run   auditctl -a exit,always -F arch=b64 -S connect -F a2!=110 -k network_outbound   to start logging outgoing connections on a host

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"
)

func main() {

	// results contains a list of maps
	var results []map[string]string

	re, err := regexp.Compile(`(?im)type=SYSCALL msg=audit\((?P<epoch>\d+.\d+):\d+\): arch=\w+ syscall=\d+ success=(?P<success>\w+) exit=?(?P<exit>\-?\d+) .* ppid=(?P<ppid>\d+) pid=(?P<pid>\d+) .* uid=(?P<uid>\d+) gid=(?P<gid>\d+) .* comm=\"(?P<comm>\w+)\" exe=\"(?P<exe>[\w\/]+)" key=\"(?P<key>\w+)\"\ntype=SOCKADDR msg=audit\(\d+.\d+:\d+\): saddr=(?P<saddr>\w+)\ntype=(?:UNKNOWN\[\d+\]|PROCTITLE) msg=audit\(\d+.\d+:\d+\): .*$`)
	if err != nil {
		log.Fatalf("There was an error. %v\n", err)
	}

	// take argument -f to set audit.log file path, current default is ./audit.log
	filename := flag.String("f", "./audit.log", "path to audit.log file")
	flag.Parse()

	// read all contents of filename into memory (this isn't a good idea for very large files)
	text, err := ioutil.ReadFile(*filename)
	if err != nil {
		log.Fatalf("Error opening file %s\n", *filename)
	}

	n1 := re.SubexpNames()

	// need to cast 'text' to string as it's actually a []byte
	result := re.FindAllStringSubmatch(string(text), -1)

	for _, v := range result {
		md := map[string]string{}
		for k, v := range v {
			if n1[k] == "epoch" {
				i, _ := strconv.ParseFloat(v, 64)
				md["timestamp"] = fmt.Sprintf("%v", time.Unix(int64(i), 0))
			}
			if n1[k] == "saddr" {
				// this is where we convert the saddr string to IPv4/6 type, Port, IP address
				s1 := v[:2]
				s2 := v[2:8]
				s3 := v[8:16]
				md["ip_raw"] = v[8:]

				// convert hex (16) to Int64
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
		// delete the "empty" key which contains the entire match, and we don't need that
		delete(md, "")
		results = append(results, md)
	}

	// need to html escape timestamp else -/+ would become &#45/&#43;
	t := template.Must(template.New("t1").Parse("{{.timestamp | html}} prog={{.exe}} uid={{.uid}} gid={{.gid}} pid={{.ppid}}:{{.pid}} exit={{.exit}} key={{.key}} type={{.iptype}} addr={{ if .ipv6 }}{{.ipv6}}{{ else }}{{.ip}}{{ end }} port={{.port}}\n"))

	for _, val := range results {
		t.Execute(os.Stdout, val)
	}

}
