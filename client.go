// Copyright 2014 NCC Group. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"probe"
)

func is_vuln_server(addr string) (bool, error) {
	/*one arg: host:port*/
	var config probe.Config
	config.InsecureSkipVerify = true
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return true, err
	}
	tlscon := probe.Client(conn, &config)
	err = tlscon.Handshake()
	if err != nil {
		if err.Error() == "remote error: bad record MAC" {
			return true, nil
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: client host:port\n")
		os.Exit(1)
	}
	vuln, err := is_vuln_server(os.Args[1])
	if err != nil {
		fmt.Printf("We couldn't run the test due to %s\n", err.Error())
		os.Exit(1)
	}
	if vuln {
		fmt.Printf("%s is vulnerable\n", os.Args[1])
	} else {
		fmt.Printf("%s is not vulnerable\n", os.Args[1])
	}
}
