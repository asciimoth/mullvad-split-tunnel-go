package demotunnel

import (
	"encoding/binary"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	want := []byte{0x45, 0, 0, 20}
	datagram := Encode(want)
	got, err := Decode(datagram)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("decoded packet = %x; want %x", got, want)
	}
	if _, err := Decode([]byte("invalid")); err == nil {
		t.Fatal("invalid datagram was accepted")
	}
}

func TestUDPReplyIPv4(t *testing.T) {
	packet := make([]byte, 20+8+4)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[20:24], 1234)
	binary.BigEndian.PutUint16(packet[22:24], 47823)
	binary.BigEndian.PutUint16(packet[24:26], 12)
	copy(packet[28:], "demo")
	reply, ok := Reply(packet)
	if !ok {
		t.Fatal("packet did not produce a reply")
	}
	if got := string(reply[28:]); got != "demo" {
		t.Fatalf("payload = %q; want demo", got)
	}
	if got := binary.BigEndian.Uint16(reply[20:22]); got != 47823 {
		t.Fatalf("source port = %d; want 47823", got)
	}
	if got := binary.BigEndian.Uint16(reply[22:24]); got != 1234 {
		t.Fatalf("destination port = %d; want 1234", got)
	}
}

func TestTCPReplyLifecycleIPv6(t *testing.T) {
	packet := make([]byte, 60)
	packet[0], packet[6], packet[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[23], packet[39] = 2, 1
	binary.BigEndian.PutUint16(packet[40:44], 1234)
	binary.BigEndian.PutUint16(packet[42:44], 47823)
	binary.BigEndian.PutUint32(packet[44:48], 50)
	packet[52], packet[53] = 5<<4, 0x02
	synAck, ok := Reply(packet)
	if !ok || synAck[53] != 0x12 {
		t.Fatalf("SYN reply = %x, %t", synAck, ok)
	}
	if got := binary.BigEndian.Uint32(synAck[48:52]); got != 51 {
		t.Fatalf("SYN acknowledgment = %d; want 51", got)
	}

	data := append(append([]byte(nil), packet...), []byte("token")...)
	binary.BigEndian.PutUint16(data[4:6], 25)
	binary.BigEndian.PutUint32(data[44:48], 51)
	binary.BigEndian.PutUint32(data[48:52], 0x10203041)
	data[53] = 0x18
	reply, ok := Reply(data)
	if !ok || string(reply[60:]) != "token" {
		t.Fatalf("data reply = %x, %t", reply, ok)
	}
	if got := binary.BigEndian.Uint32(reply[48:52]); got != 56 {
		t.Fatalf("data acknowledgment = %d; want 56", got)
	}
}
