package main

import (
    "fmt"
	"os"
	"bufio"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	tld "github.com/jpillora/go-tld"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

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
	Port int 
	Path string
}

type JsonStruct struct {
	Host string `json:"Host"`
	Ip string `json:"Ip"`
	Port int `json:"Port"`
	CertificateChain []CertChain `json:"CertificateChain"`
}

func ExtractTLDFromUrl(url string) (*TldData, error){
	var d TldData

	u, err := tld.Parse("http://"+url) // because this lib parses URLs, the protocol portion is required... It's ugly, but it works

	if u == nil {
		return nil, err
	}
	
	d.Subdomain = u.Subdomain
	d.Domain = u.Domain
	d.Tld = u.TLD
	d.Port,_ = strconv.Atoi(u.Port)
	d.Path = u.Path
	return &d, err
}



func unique(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}	
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}

func SplitAltName(r rune) bool {
    return r == ':' || r == ','  || r == ' '
}

func ExtractHostsFromCertAltNameOld(data string) []string{
	var Slice []string
	var host string

	ns := strings.Replace(data, "*.", "", -1)
	splited := strings.FieldsFunc(ns, SplitAltName)

	for _, element := range splited {
		if len(element) > 2 && strings.Contains(element, "."){
			hostdata,_ := ExtractTLDFromUrl(element)
				if hostdata != nil{
					if len(hostdata.Subdomain) > 0 {
						host = hostdata.Subdomain + "." + hostdata.Domain + "." + hostdata.Tld
					} else {
						host = hostdata.Domain + "." + hostdata.Tld
					}
					Slice = append(Slice, host)
				}
			}
	}
	uniqSlice := unique(Slice)
	return uniqSlice
}

func TokenizeHostString(data string) string{
	var HostSlice []string
	if strings.Contains(",", data) {
		eachdnsfield := strings.Split(data, ",") 				// single DNS|URI:HOST per line
		for _, element := range eachdnsfield { 					// element holds a single DNS:HOST entry
			hstring := strings.Split(element, ":")[1]			// hstring holds a single HOST part
			if strings.Contains("*.", hstring) { 
				hstring2 := strings.Replace(hstring, "*.", "")	// we have a wildcard situation, then remove it
			} else {
				hstring2 := hstring								// dont need to remove anything
			}
			if strings.Contains("://", hstring2) { 					// we have a valid URI here, 
				hoststring := strings.Split(hstring2, "://")[1]		// lets remove the protocol part
			} else {
				hoststring := hstring2								// dont need to remove anything
			}


			// validate the hoststring. It seems to be a real domain, tld etc?
			// We'll consider a "real" host:
			// Have at least 1 dot
			// Have valid tld
			if strings.Contains(".", hoststring) { // we have a dot!
				hostnameData,_ := ExtractTLDFromUrl(hoststring)
				if hostnameData != nil { // we have a domain here...
					if len(hostnameData.Subdomain) > 0 { // we have a host part / subdomain
						host = hostnameData.Subdomain + "." + hostnameData.Domain + "." + hostnameData.Tld
					} else { // we dont have a host part / subdomain, just a domain + tld
						host = hostnameData.Domain + "." + hostnameData.Tld
					}
					Slice = append(Slice, host)
				}
			}
		}
	} else { 
		// just one DNS: entry
		singlednsfield := strings.Split(data, ":")
		for _, element := range singlednsfield { 					// element holds a single DNS:HOST entry
			hstring := strings.Split(element, ":")[1]			// hstring holds a single HOST part
			if strings.Contains("*.", hstring) { 
				hoststring := strings.Replace(hstring, "*.", "")	// we have a wildcard situation, then remove it
			} else {
				hoststring := hstring								// dont need to remove anything
			}
			// validate the hoststring. It seems to be a real domain, tld etc?
			// We'll consider a "real" host:
			// Have at least 1 dot
			// Have valid tld
			if strings.Contains(".", hoststring) { // we have a dot!
				hostnameData,_ := ExtractTLDFromUrl(hoststring)
				if hostnameData != nil { // we have a domain here...
					if len(hostnameData.Subdomain) > 0 { // we have a host part / subdomain
						host = hostnameData.Subdomain + "." + hostnameData.Domain + "." + hostnameData.Tld
					} else { // we dont have a host part / subdomain, just a domain + tld
						host = hostnameData.Domain + "." + hostnameData.Tld
					}
					HostSlice = append(Slice, host)
				}
			}
		}
	}
	uniqSlice := unique(Slice)
	return uniqSlice
}

func ExtractHostsFromCertAltName(data string) []string{
	var Slice []string
	var host string
	var hl []string 

	if strings.Contains(" ", data) {
		data_nospace := strings.Replace(data, " ", "")
	} else {
		data_nospace := data
	}
	// DNS:somehost (or N)
	if strings.Contains("DNS:", data_nospace) {
		// if we have DNS:host,DNS:host ...
		hl = TokenizeHostString(data_nospace)
		for _, element := range hl { 
			Slice = append(element)
		}
	}
	if strings.Contains("URI:", data_nospace) {
		hl = TokenizeHostString(data_nospace)
		for _, element := range hl { 
			Slice = append(element)
		}	
	}

	// ignore fields: 
	// emails:
	// IP Address:
	// <EMPTY>
	// othername:
	// even if it has some new host...
	// this might be something to improve in the near future
	// for now.. it just doesnt seem to worth the effort

	}


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
			hostdata,_ := ExtractTLDFromUrl(element)
				if hostdata != nil{
					if len(hostdata.Subdomain) > 0 {
						host = hostdata.Subdomain + "." + hostdata.Domain + "." + hostdata.Tld
					} else {
						host = hostdata.Domain + "." + hostdata.Tld
					}
					Slice = append(Slice, host)
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

	jsonFile, err := os.Open("tls-scan.json")
	check(err)
	defer jsonFile.Close()

	scanner := bufio.NewScanner(jsonFile)
	for scanner.Scan() {

		err := json.Unmarshal([]byte(scanner.Text()), &jdata)
		check(err)
		/*
		fmt.Println("Host: ", jdata.Host)
		fmt.Println("IpAddress: ", jdata.Ip)
		fmt.Println("Port: ",jdata.Port)
		fmt.Println("Cert Subject: ",jdata.CertificateChain[0].Subject) 
		fmt.Println("Cert Issuer: ", jdata.CertificateChain[0].Issuer) 
		fmt.Println("Cert SubjectCN: ", jdata.CertificateChain[0].SubjectCN) 
		fmt.Println("Cert SubjectAltName: ", jdata.CertificateChain[0].SubjectAltName) 

		*/

		
		hosts := ExtractHostsFromCert(jdata.CertificateChain[0].Subject)
		for _, v := range hosts {
			hsl = append(hsl,v)
		}

		hosts = ExtractHostsFromCert(jdata.CertificateChain[0].Issuer)
		for _, v := range hosts {
			hsl = append(hsl,v)
		}

		hosts = ExtractHostsFromCert(jdata.CertificateChain[0].SubjectCN)
		for _, v := range hosts {
			hsl = append(hsl,v)
		}
		hosts = ExtractHostsFromCertAltName(jdata.CertificateChain[0].SubjectAltName)
		for _, v := range hosts {
			hsl = append(hsl,v)
		}
		
	}

	listofhosts := unique(hsl)
	for _, v := range listofhosts {
		fmt.Println(v)
	}

}
