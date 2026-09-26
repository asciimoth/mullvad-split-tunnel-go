package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExchangeTCPAndUDP(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer func() { _ = connection.Close() }()
			_, _ = io.Copy(connection, connection)
		}()
		local, remote, err := exchange("tcp4", listener.Addr().String(), "tcp-token", time.Second)
		if err != nil || local == "" || remote != listener.Addr().String() {
			t.Fatalf("exchange = %q, %q, %v", local, remote, err)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close() }()
		go func() {
			buffer := make([]byte, 64)
			length, peer, readErr := server.ReadFrom(buffer)
			if readErr == nil {
				_, _ = server.WriteTo(buffer[:length], peer)
			}
		}()
		local, remote, err := exchange("udp4", server.LocalAddr().String(), "udp-token", time.Second)
		if err != nil || local == "" || remote != server.LocalAddr().String() {
			t.Fatalf("exchange = %q, %q, %v", local, remote, err)
		}
	})
}

func TestExchangeReportsConnectionAndReplyErrors(t *testing.T) {
	if _, _, err := exchange("invalid", "127.0.0.1:1", "token", time.Second); err == nil {
		t.Fatal("invalid network was accepted")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		buffer := make([]byte, len("token"))
		_, _ = io.ReadFull(connection, buffer)
		_, _ = connection.Write([]byte("wrong"))
	}()
	if _, _, err := exchange("tcp4", listener.Addr().String(), "token", time.Second); err == nil || !strings.Contains(err.Error(), "reply was") {
		t.Fatalf("wrong reply: %v", err)
	}
}
