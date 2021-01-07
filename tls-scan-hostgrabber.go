package main

import (
	"fmt"
	"net"
	"os"
	"bufio"
	"encoding/json"
	"regexp"
	"strings"
	"github.com/bobesa/go-domain-util/domainutil"
)

type CertChain struct {
	Subject string 	`json:"Subject"`
	Issuer string `json:"Issuer"`
	SubjectCN string `json:"SubjectCN"`
	SubjectAltName string `json:"SubjectAltName"`
}

type TldData struct {
	Subdomain string
	Domain string
	Tld string
}

type JsonStruct struct {
	Host string `json:"Host"`
	Ip string `json:"Ip"`
	Port int `json:"Port"`
	CertificateChain []CertChain `json:"CertificateChain"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}


func checkIPAddressType(ip string) int {
	var retval = 9

	if net.ParseIP(ip) == nil {
        //fmt.Printf("Invalid IP Address: %s\n", ip)
        retval = 0
	}
	if retval == 9 {
		for i := 0; i < len(ip); i++ {
			switch ip[i] {
			case '.':
				//fmt.Printf("Given IP Address %s is IPV4 type\n", ip)
				retval = 4
			case ':':
				fmt.Printf("Given IP Address %s is IPV6 type\n", ip)
				//retval = 6
			}
		}
	}
	return retval
}


func ExtractTLDFromUrl(url string) (*TldData){
	var d TldData
	d.Subdomain = domainutil.Subdomain(url)
	d.Domain = domainutil.Domain(url) 
	d.Tld = domainutil.DomainSuffix(url)

	/*
	fmt.Printf("String:: %s\n", url )
	fmt.Printf("\tsub: %s\n", domainutil.Subdomain(url) )
	fmt.Printf("\tDomain: %s\n", domainutil.Domain(url) )
	fmt.Printf("\tTld: %s\n", domainutil.DomainSuffix(url) )
	*/
	return &d
}

func unique(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}	
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
			keys[entry] = true
			if len(entry) > 2 {
				list = append(list, entry)
			}
        }
    }
    return list
}

func TokenizeHostString(data string) []string {
	var hostSlice []string
	var ( 
		hoststring string
		hstring string
		host string
	)

	if strings.Contains(",", data) {
		eachdnsfield := strings.Split(data, ",") 				// single DNS|URI:HOST per line
		for _, element := range eachdnsfield { 					// element holds a single DNS:HOST entry
			if strings.Contains(":", element) { 	 
				hstring = strings.Split(element, ":")[1]			// hstring holds a single HOST part
			} else {
				hstring = element
			}
			///if strings.Contains("*.", hstring) { 
			///	hstring = strings.Replace(hstring, "*.", "", -2)	// we have a wildcard situation, then remove it
			///} else {
			///	hstring = hstring								// dont need to remove anything
			///}
			if strings.Contains("://", hstring) { 					// we have a valid URI here, 
				hoststring = strings.Split(hstring, "://")[1]		// lets remove the protocol part
			} else {
				hoststring = hstring								// dont need to remove anything
			}

			// validate the hoststring. It seems to be a real domain, tld etc?
			// We'll consider a "real" host:
			// Have at least 1 dot
			// Have valid tld
			if strings.Contains(".", hoststring) { // we have a dot!
				hostnameData := ExtractTLDFromUrl(hoststring)
				if hostnameData != nil { // we have a domain here...
					if len(hostnameData.Subdomain) > 0 { // we have a host part / subdomain
						host = hostnameData.Subdomain + "." + hostnameData.Domain //+ "." + hostnameData.Tld
					} else { // we dont have a host part / subdomain, just a domain + tld
						host = hostnameData.Domain //+ "." + hostnameData.Tld
					}
					if checkIPAddressType(host) == 0{ // not an ip address
						hostSlice = append(hostSlice, host) // not an ipaddr
					}
				
				}
			}
		}
	} else { 
		// just one DNS: entry
		singlednsfield := strings.Split(data, ":")
		for _, element := range singlednsfield { 					// element holds a single DNS:HOST entry
			hstring := strings.Split(element, ":")[1]			// hstring holds a single HOST part
			if strings.Contains("*.", hstring) { 
				hoststring = strings.Replace(hstring, "*.", "", -2)	// we have a wildcard situation, then remove it
			} else {
				hoststring = hstring								// dont need to remove anything
			}
			// validate the hoststring. It seems to be a real domain, tld etc?
			// We'll consider a "real" host:
			// Have at least 1 dot
			// Have valid tld
			if strings.Contains(".", hoststring) { // we have a dot!
				hostnameData := ExtractTLDFromUrl(hoststring)
				if hostnameData != nil { // we have a domain here...
					if len(hostnameData.Subdomain) > 0 { // we have a host part / subdomain
						host = hostnameData.Subdomain + "." + hostnameData.Domain //+ "." + hostnameData.Tld
					} else { // we dont have a host part / subdomain, just a domain + tld
						host = hostnameData.Domain // + "." + hostnameData.Tld
					}
					if checkIPAddressType(host) == 0 { // not an ip address
						hostSlice = append(hostSlice, host) // not an ipaddr
					}					
				}
			}
		}
	}
	uniqSlice := unique(hostSlice)
	return uniqSlice
}

func ExtractHostsFromCertAltName(data string) []string{
	var Slice []string
	var hl []string 
	var data_nospace string

	if strings.Contains(" ", data) {
		data_nospace = strings.ReplaceAll(data, " ", "")
	} else {
		data_nospace = data
	}
	// DNS:somehost (or N)
	if strings.Contains("DNS:", data_nospace) {
		// if we have DNS:host,DNS:host ...
		hl = TokenizeHostString(data_nospace)
		Slice = append(hl)
	}
	if strings.Contains("URI:", data_nospace) {
		hl = TokenizeHostString(data_nospace)
		Slice = append(hl)
	}

	// ignore fields: 
	// emails:
	// IP Address:
	// <EMPTY>
	// othername:
	// even if it has some new host...
	// this might be something to improve in the near future
	// for now.. it just doesnt seem to worth the effort

	uniqSlice := unique(Slice)
	return uniqSlice
}



func SplitCn(r rune) bool {
    return r == '=' || r == ';'  || r == ' '
}

func ExtractHostsFromCert(data string) []string{
	var Slice []string
	var host string

	ns := strings.Replace(data, "*.", "", -1)
	splited := strings.FieldsFunc(ns, SplitCn)

	for _, element := range splited {
		if len(element) > 2 && strings.Contains(element, "."){
			hostdata := ExtractTLDFromUrl(element)
			if hostdata != nil{
				if len(hostdata.Subdomain) > 0 {
					host = hostdata.Subdomain + "." + hostdata.Domain // + "." + hostdata.Tld
				} else {
					host = hostdata.Domain //+ "." + hostdata.Tld
				}
				if checkIPAddressType(host) == 0 { // not an ip address
					Slice = append(Slice, host)
				}
			}
		}
	}
	uniqSlice := unique(Slice)
	return uniqSlice
}

func ExtractIpAddress(data string) ([]string) {
	var Slice []string
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	if re.MatchString(data){
		submatchall := re.FindAllString(data, -1)
		for _, element := range submatchall {
			Slice = append(Slice, element)
		}
	} 
	return Slice
}

func main() {
	var jdata JsonStruct
	var hsl []string
	var hosts []string

	jsonFile, err := os.Open("tls-scan.json")
	check(err)
	defer jsonFile.Close()

	scanner := bufio.NewScanner(jsonFile)
	for scanner.Scan() {

		err := json.Unmarshal([]byte(scanner.Text()), &jdata)
		check(err)

		if len(jdata.CertificateChain[0].Subject) > 2 {
			hosts = ExtractHostsFromCert(jdata.CertificateChain[0].Subject)
			for _, v := range hosts {
				hsl = append(hsl,v)
			}
		}
		if len(jdata.CertificateChain[0].Issuer) > 2 {
			hosts = ExtractHostsFromCert(jdata.CertificateChain[0].Issuer)
			for _, v := range hosts {
				hsl = append(hsl,v)
			}
		}
		if len(jdata.CertificateChain[0].SubjectCN) > 2 {
			hosts = ExtractHostsFromCert(jdata.CertificateChain[0].SubjectCN)
			for _, v := range hosts {
				hsl = append(hsl,v)
			}
		}
		if len(jdata.CertificateChain[0].SubjectAltName) > 2 {
			hosts = ExtractHostsFromCertAltName(jdata.CertificateChain[0].SubjectAltName)
			for _, v := range hosts {
				hsl = append(hsl,v)
			}
		}
	}

	listofhosts := unique(hsl)
	for _, v := range listofhosts {
		fmt.Println(v)
	}

}
