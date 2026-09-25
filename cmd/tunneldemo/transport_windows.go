//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/asciimoth/mullvad-split-tunnel-go/internal/demotunnel"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const maxUDPPayload = 65507

func runPacketTransport(ctx context.Context, session wintun.Session, peer string) error {
	address, err := net.ResolveUDPAddr("udp", peer)
	if err != nil {
		return fmt.Errorf("resolve peer: %w", err)
	}
	connection, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return fmt.Errorf("connect to peer: %w", err)
	}
	defer func() { _ = connection.Close() }()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- copyTUNToPeer(ctx, session, connection) }()
	go func() { errorsChannel <- copyPeerToTUN(ctx, session, connection) }()
	err = <-errorsChannel
	_ = connection.Close()
	second := <-errorsChannel
	err = normalTransportShutdown(ctx, err)
	second = normalTransportShutdown(ctx, second)
	return errors.Join(err, second)
}

func normalTransportShutdown(ctx context.Context, err error) error {
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func copyTUNToPeer(ctx context.Context, session wintun.Session, connection *net.UDPConn) error {
	waitEvent := session.ReadWaitEvent()
	for {
		packet, err := session.ReceivePacket()
		if err == nil {
			if len(packet)+demotunnel.HeaderSize <= maxUDPPayload {
				_, err = connection.Write(demotunnel.Encode(packet))
			}
			session.ReleaseReceivePacket(packet)
			if err != nil {
				return fmt.Errorf("send tunnel datagram: %w", err)
			}
			continue
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return fmt.Errorf("read TUN packet: %w", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		status, err := windows.WaitForSingleObject(waitEvent, 200)
		if err != nil {
			return fmt.Errorf("wait for TUN packet: %w", err)
		}
		if status != windows.WAIT_OBJECT_0 && status != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wait for TUN packet returned %d", status)
		}
	}
}

func copyPeerToTUN(ctx context.Context, session wintun.Session, connection *net.UDPConn) error {
	buffer := make([]byte, maxUDPPayload)
	for {
		if err := connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return err
		}
		length, err := connection.Read(buffer)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			return fmt.Errorf("receive tunnel datagram: %w", err)
		}
		packet, err := demotunnel.Decode(buffer[:length])
		if err != nil {
			continue
		}
		output, err := session.AllocateSendPacket(len(packet))
		if err != nil {
			return fmt.Errorf("allocate TUN packet: %w", err)
		}
		copy(output, packet)
		session.SendPacket(output)
	}
}
