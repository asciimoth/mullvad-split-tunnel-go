package splittunnel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

type abiFixture struct {
	Configuration string
	Processes     string
	Addresses     string
	States        []uint64
	EventIDs      []uint32 `json:"event_ids"`
	Reasons       []uint32
	Events        struct {
		Start        string
		Stop         string
		ErrorStart   string `json:"error_start"`
		ErrorStop    string `json:"error_stop"`
		ErrorMessage string `json:"error_message"`
	}
	QueryRequest string `json:"query_request"`
	Query        string
	Sublayers    string
	IOCTLs       []uint32
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
	wantAddresses := Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.9.0.2"),
		InternetIPv4: netip.MustParseAddr("192.0.2.11"),
		TunnelIPv6:   netip.MustParseAddr("fd00::2"),
		InternetIPv6: netip.MustParseAddr("2001:db8::3"),
	}
	got, err = encodeAddresses(wantAddresses)
	if err != nil || !bytes.Equal(got, unhex(t, f.Addresses)) {
		t.Fatalf("addresses differ from upstream C ABI: %x, %v", got, err)
	}
	if addresses, err := decodeAddresses(unhex(t, f.Addresses)); err != nil || addresses != wantAddresses {
		t.Fatalf("decode C addresses: %+v, %v", addresses, err)
	}
	if !reflect.DeepEqual(f.States, []uint64{0, 1, 2, 3, 4, 5}) {
		t.Fatalf("states differ from upstream enum: %v", f.States)
	}
	for _, value := range f.States {
		b := make([]byte, 8)
		le.PutUint64(b, value)
		if state, err := decodeState(b); err != nil || uint64(state) != value {
			t.Fatalf("decode C state %d: %v, %v", value, state, err)
		}
	}
	if !reflect.DeepEqual(f.EventIDs, []uint32{0, 1, 0x80000001, 0x80000002, 0x80000003}) {
		t.Fatalf("event IDs differ from upstream enum: %v", f.EventIDs)
	}
	if !reflect.DeepEqual(f.Reasons, []uint32{1, 2, 4, 8}) {
		t.Fatalf("event reasons differ from upstream enum: %v", f.Reasons)
	}
	eventCases := []struct {
		name      string
		wire      string
		id        EventID
		reason    Reason
		message   string
		status    uint32
		imagePath string
	}{
		{"start", f.Events.Start, EventStartSplitting, ReasonConfig | ReasonArriving, "", 0, fixturePaths()[0]},
		{"stop", f.Events.Stop, EventStopSplitting, ReasonDeparting, "", 0, fixturePaths()[0]},
		{"error start", f.Events.ErrorStart, EventErrorStartSplitting, 0, "", 0, fixturePaths()[0]},
		{"error stop", f.Events.ErrorStop, EventErrorStopSplitting, 0, "", 0, fixturePaths()[0]},
		{"error message", f.Events.ErrorMessage, EventErrorMessage, 0, "driver error", 0xc0000001, ""},
	}
	for _, test := range eventCases {
		t.Run(test.name, func(t *testing.T) {
			event, err := decodeEvent(unhex(t, test.wire))
			wantPID := uint32(0)
			if test.imagePath != "" {
				wantPID = 42
			}
			if err != nil || event.ID != test.id || event.PID != wantPID ||
				event.Reason != test.reason || event.ImagePath != test.imagePath ||
				event.Message != test.message || event.NTStatus != test.status {
				t.Fatalf("decode C event: %+v, %v", event, err)
			}
		})
	}
	process, err := decodeProcess(unhex(t, f.Query))
	if err != nil || process.PID != 42 || process.ParentPID != 7 ||
		!process.Split || process.ImagePath != fixturePaths()[0] {
		t.Fatalf("decode C query with trailing struct padding: %+v, %v", process, err)
	}
	queryRequest := make([]byte, 8)
	le.PutUint64(queryRequest, 42)
	if !bytes.Equal(queryRequest, unhex(t, f.QueryRequest)) {
		t.Fatalf("process query request differs from upstream C ABI: %x", queryRequest)
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

func TestRejectMalformedABIResponses(t *testing.T) {
	f := loadFixture(t)
	for _, b := range [][]byte{nil, make([]byte, addressesSize-1), make([]byte, addressesSize+1)} {
		if _, err := decodeAddresses(b); !errors.Is(err, ErrProtocol) {
			t.Errorf("accepted address response of length %d: %v", len(b), err)
		}
	}
	for name, b := range map[string][]byte{
		"short":   make([]byte, 7),
		"unknown": {6, 0, 0, 0, 0, 0, 0, 0},
	} {
		t.Run("state "+name, func(t *testing.T) {
			if _, err := decodeState(b); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted malformed state: %v", err)
			}
		})
	}
	events := map[string][]byte{
		"start":         unhex(t, f.Events.Start),
		"stop":          unhex(t, f.Events.Stop),
		"error start":   unhex(t, f.Events.ErrorStart),
		"error stop":    unhex(t, f.Events.ErrorStop),
		"error message": unhex(t, f.Events.ErrorMessage),
	}
	for name, valid := range events {
		t.Run("truncated "+name, func(t *testing.T) {
			b := bytes.Clone(valid[:len(valid)-1])
			le.PutUint64(b[8:], uint64(len(b)-eventHeaderSize))
			if _, err := decodeEvent(b); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted truncated event: %v", err)
			}
		})
	}
	for name, reason := range map[string]uint32{"zero": 0, "unknown bit": 16} {
		t.Run("reason "+name, func(t *testing.T) {
			b := unhex(t, f.Events.Start)
			le.PutUint32(b[eventHeaderSize+8:], reason)
			if _, err := decodeEvent(b); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted malformed event reason: %v", err)
			}
		})
	}
	for _, fixture := range []string{f.Events.Start, f.Events.ErrorStart} {
		b := unhex(t, fixture)
		le.PutUint64(b[eventHeaderSize:], uint64(^uint32(0))+1)
		if _, err := decodeEvent(b); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted event PID outside uint32: %v", err)
		}
	}
	query := unhex(t, f.Query)
	for name, mutate := range map[string]func([]byte) []byte{
		"short":           func(b []byte) []byte { return b[:21] },
		"invalid boolean": func(b []byte) []byte { b[16] = 2; return b },
		"wrong length":    func(b []byte) []byte { le.PutUint16(b[18:], 2); return b },
		"oversized PID":   func(b []byte) []byte { le.PutUint64(b, uint64(^uint32(0))+1); return b },
	} {
		t.Run("query "+name, func(t *testing.T) {
			if _, err := decodeProcess(mutate(bytes.Clone(query))); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted malformed query response: %v", err)
			}
		})
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

func TestPinnedDriverSplittingErrorCompatibility(t *testing.T) {
	// Driver 1.3.0.0 calls BuildSplittingErrorEvent(..., false) from both
	// BuildStartSplittingErrorEvent and BuildStopSplittingErrorEvent. Consumers
	// must therefore handle both ABI values as a direction-unknown process error.
	for _, id := range []EventID{EventErrorStartSplitting, EventErrorStopSplitting} {
		b := make([]byte, eventHeaderSize+10)
		le.PutUint32(b, uint32(id))
		le.PutUint64(b[8:], 10)
		le.PutUint64(b[eventHeaderSize:], 42)
		event, err := decodeEvent(b)
		if err != nil || event.ID != id || event.PID != 42 || !event.ID.IsSplittingError() {
			t.Fatalf("splitting error %#x = %+v, %v", id, event, err)
		}
	}
	for _, id := range []EventID{
		EventStartSplitting, EventStopSplitting, EventErrorMessage, EventID(0x80000004),
	} {
		if id.IsSplittingError() {
			t.Errorf("non-splitting error ID %#x reported as splitting error", id)
		}
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

func TestPublicValueFormatting(t *testing.T) {
	states := []string{"none", "started", "initialized", "ready", "engaged", "zombie"}
	for value, want := range states {
		if got := State(value).String(); got != want {
			t.Errorf("State(%d).String() = %q; want %q", value, got, want)
		}
	}
	if got := State(99).String(); got != "unknown(99)" {
		t.Fatalf("unknown state string = %q", got)
	}
	for _, value := range []string{
		"", "00112233", "{00112233-4455-6677-8899-aabbccddeeff",
		"00112233_4455-6677-8899-aabbccddeeff", "zz112233-4455-6677-8899-aabbccddeeff",
	} {
		if _, err := ParseGUID(value); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ParseGUID(%q): %v", value, err)
		}
	}
}

func FuzzDriverDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	data, err := os.ReadFile("testdata/abi.json")
	if err == nil {
		var fixture abiFixture
		if json.Unmarshal(data, &fixture) == nil {
			for _, s := range []string{fixture.Configuration, fixture.Query, fixture.Events.Start,
				fixture.Events.Stop, fixture.Events.ErrorStart, fixture.Events.ErrorStop,
				fixture.Events.ErrorMessage} {
				b, _ := hex.DecodeString(s)
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > eventBufferSize {
			t.Skip()
		}
		_, _ = decodeConfigurationSize(b)
		_, _ = decodeConfiguration(b)
		_, _ = decodeAddresses(b)
		_, _ = decodeState(b)
		_, _ = decodeEvent(b)
		_, _ = decodeProcess(b)
	})
}

func FuzzGUID(f *testing.F) {
	f.Add("")
	f.Add("00112233-4455-6677-8899-aabbccddeeff")
	f.Add("{ffeeddcc-bbaa-9988-7766-554433221100}")
	f.Add("zz112233-4455-6677-8899-aabbccddeeff")
	f.Fuzz(func(t *testing.T, input string) {
		guid, err := ParseGUID(input)
		if err != nil {
			return
		}
		roundTrip, err := ParseGUID(guid.String())
		if err != nil || roundTrip != guid {
			t.Fatalf("GUID round trip = %v, %v; want %v", roundTrip, err, guid)
		}
	})
}

func FuzzConfigurationRoundTrip(f *testing.F) {
	f.Add([]byte("app.exe"))
	f.Add([]byte{0, 1, 2, 0xff})
	f.Add([]byte("beta-β"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		// Hex produces a valid, exact NT device path for every byte sequence.
		path := `\Device\Fuzz\` + hex.EncodeToString(input) + ".exe"
		encoded, err := encodeConfiguration([]string{path})
		if err != nil {
			t.Fatalf("encode generated path: %v", err)
		}
		decoded, err := decodeConfiguration(encoded)
		if err != nil || !reflect.DeepEqual(decoded, []string{path}) {
			t.Fatalf("configuration round trip: %v, %v", decoded, err)
		}
		processes := []Process{
			{PID: 1, ImagePath: path},
			{PID: 2, ParentPID: 1},
		}
		if _, err := encodeProcesses(processes); err != nil {
			t.Fatalf("encode generated process tree: %v", err)
		}
	})
}

func FuzzProcessEncoding(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 0xff})
	f.Add([]byte("process-tree-seed"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		count := len(input) + 1
		processes := make([]Process, count)
		for i := range processes {
			processes[i].PID = uint32(i + 1)
			if i != 0 {
				processes[i].ParentPID = uint32(input[i-1]) % uint32(i+1)
			}
			if i < len(input) && input[i]&1 != 0 {
				processes[i].ImagePath = fmt.Sprintf(`\Device\Fuzz\%d-%02x.exe`, i, input[i])
			}
		}
		encoded, err := encodeProcesses(processes)
		if err != nil {
			t.Fatalf("encode generated process tree: %v", err)
		}
		if got := le.Uint64(encoded); got != uint64(count) {
			t.Fatalf("encoded count = %d; want %d", got, count)
		}
		if got := le.Uint64(encoded[8:]); got != uint64(len(encoded)) {
			t.Fatalf("encoded size = %d; want %d", got, len(encoded))
		}
		stringsStart := configHeaderSize + count*processEntrySize
		for i, process := range processes {
			entry := encoded[configHeaderSize+i*processEntrySize:]
			if got := le.Uint64(entry); got != uint64(process.PID) {
				t.Fatalf("process %d PID = %d; want %d", i, got, process.PID)
			}
			if got := le.Uint64(entry[8:]); got != uint64(process.ParentPID) {
				t.Fatalf("process %d parent = %d; want %d", i, got, process.ParentPID)
			}
			offset := int(le.Uint64(entry[16:]))
			size := int(le.Uint16(entry[24:]))
			if offset < 0 || size < 0 || offset+size > len(encoded)-stringsStart {
				t.Fatalf("process %d string range = %d+%d", i, offset, size)
			}
			path, err := decodeWide(encoded[stringsStart+offset : stringsStart+offset+size])
			if err != nil || path != process.ImagePath {
				t.Fatalf("process %d path = %q, %v; want %q", i, path, err, process.ImagePath)
			}
		}
	})
}
