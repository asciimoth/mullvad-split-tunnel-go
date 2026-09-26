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
	local, remote, err := exchange(*network, *address, *token, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("path-ok network=%s local=%s remote=%s token=%q\n", *network, local, remote, *token)
}

func exchange(network, address, token string, timeout time.Duration) (string, string, error) {
	connection, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", "", err
	}
	if _, err := connection.Write([]byte(token)); err != nil {
		return "", "", err
	}
	reply := make([]byte, len(token))
	if _, err := io.ReadFull(connection, reply); err != nil {
		return "", "", err
	}
	if string(reply) != token {
		return "", "", fmt.Errorf("reply was %q, not %q", reply, token)
	}
	return connection.LocalAddr().String(), connection.RemoteAddr().String(), nil
}
