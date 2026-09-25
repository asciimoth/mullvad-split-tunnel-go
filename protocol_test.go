package splittunnel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

type abiFixture struct {
	Configuration string
	Processes     string
	Event         string
	Query         string
	Sublayers     string
	IOCTLs        []uint32
}

func loadFixture(t *testing.T) abiFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/abi.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture abiFixture
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixturePaths() []string {
	return []string{"\\Device\\X\\app.exe", "\\Device\\X\\β🦋.exe"}
}

func TestABIFromUpstreamHeaders(t *testing.T) {
	f := loadFixture(t)
	got, err := encodeConfiguration(fixturePaths())
	if err != nil || !bytes.Equal(got, unhex(t, f.Configuration)) {
		t.Fatalf("configuration differs from upstream C ABI: %x, %v", got, err)
	}
	paths, err := decodeConfiguration(unhex(t, f.Configuration))
	if err != nil || !reflect.DeepEqual(paths, fixturePaths()) {
		t.Fatalf("decode C configuration: %v, %v", paths, err)
	}
	got, err = encodeProcesses([]Process{{PID: 42, ParentPID: 7, ImagePath: fixturePaths()[0]}})
	if err != nil || !bytes.Equal(got, unhex(t, f.Processes)) {
		t.Fatalf("process registry differs from upstream C ABI: %x, %v", got, err)
	}
	event, err := decodeEvent(unhex(t, f.Event))
	if err != nil || event.ID != EventStartSplitting || event.PID != 42 ||
		event.Reason != ReasonConfig|ReasonArriving || event.ImagePath != fixturePaths()[0] {
		t.Fatalf("decode C event: %+v, %v", event, err)
	}
	process, err := decodeProcess(unhex(t, f.Query))
	if err != nil || process.PID != 42 || process.ParentPID != 7 ||
		!process.Split || process.ImagePath != fixturePaths()[0] {
		t.Fatalf("decode C query with trailing struct padding: %+v, %v", process, err)
	}
	a, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	b, _ := ParseGUID("{ffeeddcc-bbaa-9988-7766-554433221100}")
	got, err = encodeSublayers(Sublayers{a, b})
	if err != nil || !bytes.Equal(got, unhex(t, f.Sublayers)) {
		t.Fatalf("GUID byte order differs from Windows C layout: %x, %v", got, err)
	}
	if a.String() != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("GUID string: %s", a)
	}
	ioctls := []uint32{ioctlInitialize, ioctlDequeueEvent, ioctlRegisterProcesses,
		ioctlRegisterAddresses, ioctlGetAddresses, ioctlSetConfiguration,
		ioctlGetConfiguration, ioctlClearConfiguration, ioctlGetState,
		ioctlQueryProcess, ioctlReset}
	if !reflect.DeepEqual(ioctls, f.IOCTLs) {
		t.Fatalf("IOCTLs differ from upstream CTL_CODE values: %x versus %x", ioctls, f.IOCTLs)
	}
}

func TestRejectMalformedConfiguration(t *testing.T) {
	valid := unhex(t, loadFixture(t).Configuration)
	mutations := map[string]func([]byte) []byte{
		"short":            func(b []byte) []byte { return b[:15] },
		"overflow count":   func(b []byte) []byte { le.PutUint64(b, ^uint64(0)); return b },
		"wrong total":      func(b []byte) []byte { le.PutUint64(b[8:], 16); return b },
		"overflow offset":  func(b []byte) []byte { le.PutUint64(b[16:], ^uint64(0)-1); return b },
		"unaligned offset": func(b []byte) []byte { le.PutUint64(b[16:], 1); return b },
		"odd length":       func(b []byte) []byte { le.PutUint16(b[24:], 3); return b },
		"bad surrogate":    func(b []byte) []byte { le.PutUint16(b[48:], 0xdc00); return b },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfiguration(mutate(bytes.Clone(valid))); !errors.Is(err, ErrProtocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		})
	}
}

func TestPathAndProcessValidation(t *testing.T) {
	for _, path := range []string{"", "app.exe", "C:\\app.exe", "\\Device\\X\\*.exe",
		"\\Device\\X\\..\\a.exe", "\\Device\\X\\a\x00.exe", "\\Device\\X\\" + strings.Repeat("x", 32768)} {
		if _, err := encodeConfiguration([]string{path}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("accepted invalid path of length %d: %v", len(path), err)
		}
	}
	for _, processes := range [][]Process{
		nil, {{PID: 0}}, {{PID: 1, ParentPID: 1}}, {{PID: 1}, {PID: 1}},
		{{PID: 1, ParentPID: 2}, {PID: 2, ParentPID: 1}},
	} {
		if _, err := encodeProcesses(processes); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("accepted invalid process graph %+v: %v", processes, err)
		}
	}
	unknown, err := encodeProcesses([]Process{{PID: 4}})
	if err != nil || len(unknown) != 50 || le.Uint64(unknown[8:]) != 50 {
		t.Fatalf("pathless snapshot needs a nonempty string region: %x, %v", unknown, err)
	}
}

func TestAddressesWireOrderAndMissingFamilies(t *testing.T) {
	input := Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.9.0.2"),
		InternetIPv4: netip.MustParseAddr("192.0.2.11"),
		TunnelIPv6:   netip.MustParseAddr("fd00::2"),
	}
	b, err := encodeAddresses(input)
	want := unhex(t, "0a090002c000020bfd00000000000000000000000000000200000000000000000000000000000000")
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("address order/bytes: %x, %v", b, err)
	}
	decoded, err := decodeAddresses(b)
	if err != nil || decoded != input {
		t.Fatalf("addresses: %+v, %v", decoded, err)
	}
	for _, invalid := range []Addresses{
		{TunnelIPv4: netip.MustParseAddr("fd00::2")},
		{InternetIPv6: netip.MustParseAddr("fe80::1%12")},
		{InternetIPv6: netip.MustParseAddr("fe80::1")},
		{InternetIPv6: netip.MustParseAddr("::ffff:192.0.2.1")},
		{TunnelIPv4: input.TunnelIPv4, InternetIPv4: input.TunnelIPv4},
	} {
		if _, err := encodeAddresses(invalid); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("accepted invalid addresses %+v", invalid)
		}
	}
}

func TestEventErrorsAndUnknownIDs(t *testing.T) {
	b := make([]byte, 24)
	le.PutUint32(b, uint32(EventErrorMessage))
	le.PutUint64(b[8:], 8)
	le.PutUint32(b[16:], 0xc0000001)
	le.PutUint16(b[20:], 2)
	le.PutUint16(b[22:], 'X')
	e, err := decodeEvent(b)
	if err != nil || e.Message != "X" || e.NTStatus != 0xc0000001 {
		t.Fatalf("NTSTATUS event: %+v, %v", e, err)
	}
	le.PutUint32(b, 1234)
	e, err = decodeEvent(b)
	if err != nil || !bytes.Equal(e.Raw, b[16:]) {
		t.Fatalf("unknown event payload not preserved: %+v, %v", e, err)
	}
	b[16] = 42
	if e.Raw[0] == 42 {
		t.Fatal("event payload aliases caller memory")
	}
	le.PutUint64(b[8:], ^uint64(0))
	if _, err := decodeEvent(b); !errors.Is(err, ErrProtocol) {
		t.Fatalf("accepted overflowing event length: %v", err)
	}
}

func TestSnapshotDoesNotInheritFromRecycledPID(t *testing.T) {
	input := []Process{
		{PID: 30, ParentPID: 10, CreationTime: 100},
		{PID: 10, CreationTime: 200},
		{PID: 40, ParentPID: 10, CreationTime: 300},
		{PID: 50, ParentPID: 10},
	}
	result := normalizeSnapshot(input)
	if result[1].ParentPID != 0 || result[2].ParentPID != 10 || result[3].ParentPID != 0 {
		t.Fatalf("incorrect parent normalization: %+v", result)
	}
	if input[0].ParentPID != 10 || input[0].PID != 30 {
		t.Fatal("snapshot normalization changed caller-owned data")
	}
}

func FuzzDriverDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	data, err := os.ReadFile("testdata/abi.json")
	if err == nil {
		var fixture abiFixture
		if json.Unmarshal(data, &fixture) == nil {
			for _, s := range []string{fixture.Configuration, fixture.Event, fixture.Query} {
				b, _ := hex.DecodeString(s)
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > eventBufferSize {
			t.Skip()
		}
		_, _ = decodeConfiguration(b)
		_, _ = decodeEvent(b)
		_, _ = decodeProcess(b)
	})
}
