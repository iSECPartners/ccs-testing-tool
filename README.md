This is a tool to test servers for CVE-2014-0224.

To build:

    $ export GOPATH=$(pwd)
    $ go build client.go

To run:

    $ ./client example.com:443
    example.com:443 is not vulnerable
