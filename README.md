# tls-scan-hostgrabber
Parse tls-scan json output and fetch all hostnames and IPs from Subject, SubjectCN, Issuer and SubjectAltName fields

# About TLS-SCAN

tls-scan (https://github.com/prbinu/tls-scan) is a fantastic tool written by @prbinu that grabs the TLS certificate from a given host (or a list of hosts), parses and produces a ndjson file with all the information taken from the certificate.

# About tls-scan-hostgrabber

I'm learning GO the hard way, which consist of taking my Python tools and port it to Go.
You can expect bad Go code that just works.

With this in mind, in order to use tls-scan-hostgrabber, you must first run tls-scan and create a tls-scan.json file with the output of tls-scan tool (ndjson).
Place the tls-scan.json in the same directory as main.go / main binary file.


# Install and Run

git clone github.com/dogasantos/tls-scan-hostgrabber
cd tls-scan-hostgrabber
go build main.go
./main > output.txt

The output.txt will contain all the hostnames and ip addressess found inside tls-scan.json certificate data.

