// Command flowprobe exchanges one token with a controlled TCP or UDP echo
// endpoint. It is a diagnostic helper for the tunnel demonstration.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	network := flag.String("network", "tcp4", "tcp4, tcp6, udp4, or udp6")
	address := flag.String("address", "", "echo endpoint address")
	token := flag.String("token", "FLOWPROBE", "token to exchange")
	timeout := flag.Duration("timeout", 3*time.Second, "operation timeout")
	flag.Parse()
	if *address == "" {
		fmt.Fprintln(os.Stderr, "-address is required")
		os.Exit(2)
	}
	connection, err := net.DialTimeout(*network, *address, *timeout)
	if err == nil {
		err = connection.SetDeadline(time.Now().Add(*timeout))
	}
	if err == nil {
		_, err = connection.Write([]byte(*token))
	}
	reply := make([]byte, len(*token))
	if err == nil {
		_, err = io.ReadFull(connection, reply)
	}
	if connection != nil {
		defer func() { _ = connection.Close() }()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if string(reply) != *token {
		fmt.Fprintf(os.Stderr, "reply was %q, not %q\n", reply, *token)
		os.Exit(1)
	}
	fmt.Printf("path-ok network=%s local=%s remote=%s token=%q\n", *network, connection.LocalAddr(), connection.RemoteAddr(), *token)
}
