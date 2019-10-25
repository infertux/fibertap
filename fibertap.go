package main

import (
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	var err error

	err = exec.Command("iptables", "-N", "fibertap").Run()
	if err != nil {
		log.Print("Couldn't create chain fibertap, does it already exist?")
	}
	err = exec.Command("iptables", "-F", "fibertap").Run()
	if err != nil {
		log.Fatal("Couldn't flush chain fibertap")
	}
	err = exec.Command("iptables", "-A", "fibertap", "-j", "RETURN").Run()
	if err != nil {
		log.Fatal("Couldn't set up chain fibertap")
	}
	err = exec.Command("iptables", "-D", "OUTPUT", "-j", "fibertap").Run()
	if err != nil {
		log.Print("Couldn't delete jump to chain fibertap")
	}
	err = exec.Command("iptables", "-I", "OUTPUT", "-j", "fibertap").Run()
	if err != nil {
		log.Fatal("Couldn't jump to chain fibertap")
	}

	blacklist := map[string]int{}

	geoip, err := geoip2.Open("/usr/share/GeoIP/GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer geoip.Close()

	for {
		output, err := exec.Command("/usr/bin/ss", "-HOntu").Output()
		if err != nil {
			log.Fatal(err)
		}
		// fmt.Printf("%s\n", output)

		remoteRegexp := regexp.MustCompile(`\s+\S+:\S+\s*\n`)
		matches := remoteRegexp.FindAll(output, -1)
		for _, match := range matches {
			hostport := strings.TrimSpace(string(match[:]))
			host, _, err := net.SplitHostPort(hostport)
			if err != nil {
				log.Fatal(err)
			}
			if host == "127.0.0.1" || host == "::1" {
				continue
			}

			if _, ok := blacklist[host]; ok {
				blacklist[host]++
				continue
			}

			ip := net.ParseIP(host)

			record, err := geoip.Country(ip)
			if err != nil {
				log.Fatal(err)
			}

			country := record.Country.IsoCode
			if country != "US" && country != "NL" && country != "XX" {
				fmt.Printf("Ignoring %s (%s)\n", host, country)
			} else {
				if ip.To4() == nil {
					log.Printf("FIXME: handle IPv6 %v (%s)", ip, country)
					continue
				}

				fmt.Printf("Blocking %s (%s)\n", host, country)

				cmd := exec.Command("iptables", "-I", "fibertap", "-d", host, "-j", "REJECT")
				err := cmd.Run()
				if err != nil {
					log.Fatalf("Failed to reject %s: %v", host, err)
				}

				blacklist[host] = 1
			}
		}

		time.Sleep(1000 * time.Millisecond)
	}
}
