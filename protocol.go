package splittunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Explicit 64-bit ABI sizes: encoding/binary does not insert C padding.
const (
	configHeaderSize  = 16
	configEntrySize   = 16
	processEntrySize  = 32
	addressesSize     = 40
	eventHeaderSize   = 16
	maxBufferSize     = 16 << 20 // Local bound, below upstream's 100 MB limit.
	maxRecords        = 65536
	eventBufferSize   = 128 << 10
	processBufferSize = 128 << 10

	ioctlInitialize         uint32 = 0x80000004
	ioctlDequeueEvent       uint32 = 0x80000008
	ioctlRegisterProcesses  uint32 = 0x8000000c
	ioctlRegisterAddresses  uint32 = 0x80000010
	ioctlGetAddresses       uint32 = 0x80000014
	ioctlSetConfiguration   uint32 = 0x80000018
	ioctlGetConfiguration   uint32 = 0x8000001c
	ioctlClearConfiguration uint32 = 0x80000023
	ioctlGetState           uint32 = 0x80000024
	ioctlQueryProcess       uint32 = 0x80000028
	ioctlReset              uint32 = 0x8000002f
)

var le = binary.LittleEndian

func encodeSublayers(s Sublayers) ([]byte, error) {
	if s.Baseline == (GUID{}) || s.DNS == (GUID{}) || s.Baseline == s.DNS {
		return nil, fmt.Errorf("%w: sublayers must be nonzero and distinct", ErrInvalidArgument)
	}
	b := make([]byte, 32)
	copy(b[:16], s.Baseline[:])
	copy(b[16:], s.DNS[:])
	return b, nil
}

func encodePath(s string, allowEmpty bool) ([]byte, error) {
	if s == "" && allowEmpty {
		return nil, nil
	}
	if !utf8.ValidString(s) || len(s) > 4*32767 ||
		!strings.HasPrefix(strings.ToLower(s), "\\device\\") ||
		len(s) <= len("\\Device\\") || strings.HasSuffix(s, "\\") ||
		strings.ContainsAny(s, "\x00/*?") {
		return nil, fmt.Errorf("%w: expected an exact NT device path", ErrInvalidArgument)
	}
	for _, part := range strings.Split(s, "\\") {
		if part == "." || part == ".." {
			return nil, fmt.Errorf("%w: device path contains a dot component", ErrInvalidArgument)
		}
	}
	units := utf16.Encode([]rune(s))
	if len(units) > 32767 {
		return nil, fmt.Errorf("%w: path exceeds the USHORT byte-length limit", ErrInvalidArgument)
	}
	b := make([]byte, len(units)*2)
	for i, u := range units {
		le.PutUint16(b[i*2:], u)
	}
	return b, nil
}

func decodeWide(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: odd UTF-16 byte length", ErrProtocol)
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = le.Uint16(b[i*2:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", fmt.Errorf("%w: embedded NUL", ErrProtocol)
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: unpaired UTF-16 surrogate", ErrProtocol)
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("%w: unpaired UTF-16 surrogate", ErrProtocol)
		}
	}
	return string(utf16.Decode(units)), nil
}

func encodeConfiguration(paths []string) ([]byte, error) {
	if len(paths) == 0 || len(paths) > maxRecords {
		return nil, fmt.Errorf("%w: configuration needs 1..%d paths", ErrInvalidArgument, maxRecords)
	}
	stringsStart := configHeaderSize + len(paths)*configEntrySize
	total := stringsStart
	names := make([][]byte, len(paths))
	for i, path := range paths {
		name, err := encodePath(path, false)
		if err != nil {
			return nil, fmt.Errorf("path %d: %w", i, err)
		}
		names[i] = name
		total += len(name)
		if total > maxBufferSize {
			return nil, fmt.Errorf("%w: configuration exceeds local buffer limit", ErrInvalidArgument)
		}
	}
	b := make([]byte, total)
	le.PutUint64(b, uint64(len(paths)))
	le.PutUint64(b[8:], uint64(total))
	cursor := stringsStart
	for i, name := range names {
		entry := b[configHeaderSize+i*configEntrySize:]
		le.PutUint64(entry, uint64(cursor-stringsStart))
		le.PutUint16(entry[8:], uint16(len(name)))
		copy(b[cursor:], name)
		cursor += len(name)
	}
	return b, nil
}

func decodeConfiguration(b []byte) ([]string, error) {
	if len(b) < configHeaderSize || len(b) > maxBufferSize {
		return nil, fmt.Errorf("%w: configuration header/size", ErrProtocol)
	}
	count, total := le.Uint64(b), le.Uint64(b[8:])
	if count > maxRecords || total != uint64(len(b)) ||
		count > uint64((len(b)-configHeaderSize)/configEntrySize) {
		return nil, fmt.Errorf("%w: configuration count/length", ErrProtocol)
	}
	stringsStart := configHeaderSize + int(count)*configEntrySize
	stringsData := b[stringsStart:]
	paths := make([]string, int(count))
	for i := range paths {
		entry := b[configHeaderSize+i*configEntrySize:]
		offset, size := le.Uint64(entry), uint64(le.Uint16(entry[8:]))
		if size == 0 || offset%2 != 0 || size%2 != 0 ||
			offset > uint64(len(stringsData)) || size > uint64(len(stringsData))-offset {
			return nil, fmt.Errorf("%w: path %d range", ErrProtocol, i)
		}
		path, err := decodeWide(stringsData[int(offset):int(offset+size)])
		if err != nil {
			return nil, err
		}
		if _, err := encodePath(path, false); err != nil {
			return nil, fmt.Errorf("%w: invalid returned device path", ErrProtocol)
		}
		paths[i] = path
	}
	return paths, nil
}

func validateProcessTree(processes []Process) error {
	if len(processes) == 0 || len(processes) > maxRecords {
		return fmt.Errorf("%w: process snapshot needs 1..%d records", ErrInvalidArgument, maxRecords)
	}
	parents := make(map[uint32]uint32, len(processes))
	for _, p := range processes {
		_, duplicate := parents[p.PID]
		if p.PID == 0 || p.PID == p.ParentPID || duplicate {
			return fmt.Errorf("%w: invalid/duplicate process PID %d", ErrInvalidArgument, p.PID)
		}
		parents[p.PID] = p.ParentPID
	}
	// Iterative graph validation avoids recursion on an untrusted deep tree.
	done := make(map[uint32]bool, len(processes))
	for _, p := range processes {
		path := make(map[uint32]bool)
		pid := p.PID
		for pid != 0 && !done[pid] {
			parent, exists := parents[pid]
			if !exists {
				break
			}
			if path[pid] {
				return fmt.Errorf("%w: cyclic process ancestry", ErrInvalidArgument)
			}
			path[pid] = true
			pid = parent
		}
		for pid := range path {
			done[pid] = true
		}
	}
	return nil
}

func encodeProcesses(processes []Process) ([]byte, error) {
	if err := validateProcessTree(processes); err != nil {
		return nil, err
	}
	stringsStart := configHeaderSize + len(processes)*processEntrySize
	total := stringsStart
	names := make([][]byte, len(processes))
	for i, p := range processes {
		name, err := encodePath(p.ImagePath, true)
		if err != nil {
			return nil, fmt.Errorf("PID %d: %w", p.PID, err)
		}
		names[i] = name
		total += len(name)
		if total > maxBufferSize {
			return nil, fmt.Errorf("%w: process snapshot exceeds local buffer limit", ErrInvalidArgument)
		}
	}
	// The pinned driver's validator requires the string region to be nonempty,
	// even when every process has an unknown (zero-length) image name.
	if total == stringsStart {
		total += 2
	}
	b := make([]byte, total)
	le.PutUint64(b, uint64(len(processes)))
	le.PutUint64(b[8:], uint64(total))
	cursor := stringsStart
	for i, p := range processes {
		entry := b[configHeaderSize+i*processEntrySize:]
		le.PutUint64(entry, uint64(p.PID))
		le.PutUint64(entry[8:], uint64(p.ParentPID))
		le.PutUint64(entry[16:], uint64(cursor-stringsStart))
		le.PutUint16(entry[24:], uint16(len(names[i])))
		copy(b[cursor:], names[i])
		cursor += len(names[i])
	}
	return b, nil
}

func encodeAddresses(a Addresses) ([]byte, error) {
	b := make([]byte, addressesSize)
	entries := []struct {
		addr netip.Addr
		dst  []byte
		v4   bool
	}{
		{a.TunnelIPv4, b[0:4], true},
		{a.InternetIPv4, b[4:8], true},
		{a.TunnelIPv6, b[8:24], false},
		{a.InternetIPv6, b[24:40], false},
	}
	for _, entry := range entries {
		if !entry.addr.IsValid() {
			continue
		}
		addr := entry.addr
		if entry.v4 {
			addr = addr.Unmap()
		}
		if addr.Zone() != "" || addr.Is4() != entry.v4 ||
			(!entry.v4 && addr.Is4In6()) || addr.IsLoopback() ||
			addr.IsMulticast() || (!entry.v4 && addr.IsLinkLocalUnicast()) {
			return nil, fmt.Errorf("%w: invalid address for driver role: %s", ErrInvalidArgument, addr)
		}
		copy(entry.dst, addr.AsSlice())
	}
	for _, pair := range [][2]netip.Addr{{a.TunnelIPv4, a.InternetIPv4}, {a.TunnelIPv6, a.InternetIPv6}} {
		if pair[0].IsValid() && !pair[0].IsUnspecified() && pair[0].Unmap() == pair[1].Unmap() {
			return nil, fmt.Errorf("%w: tunnel and Internet addresses must differ", ErrInvalidArgument)
		}
	}
	return b, nil
}

func decodeAddresses(b []byte) (Addresses, error) {
	if len(b) != addressesSize {
		return Addresses{}, fmt.Errorf("%w: address buffer size", ErrProtocol)
	}
	read := func(data []byte) netip.Addr {
		a, _ := netip.AddrFromSlice(data)
		if a.IsUnspecified() {
			return netip.Addr{}
		}
		return a
	}
	return Addresses{read(b[:4]), read(b[4:8]), read(b[8:24]), read(b[24:40])}, nil
}

func decodePID(b []byte) (uint32, error) {
	if len(b) < 8 || le.Uint64(b) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("%w: invalid PID-sized HANDLE", ErrProtocol)
	}
	return uint32(le.Uint64(b)), nil
}

func decodeProcess(b []byte) (ProcessStatus, error) {
	var p ProcessStatus
	// The C structure has its ImageName at offset 20, sizeof == 24. The driver
	// returns sizeof-2+nameLength bytes; accept the resulting trailing padding.
	if len(b) < 22 {
		return p, fmt.Errorf("%w: short process response", ErrProtocol)
	}
	var err error
	if p.PID, err = decodePID(b); err != nil {
		return p, err
	}
	if p.ParentPID, err = decodePID(b[8:]); err != nil {
		return p, err
	}
	if b[16] > 1 {
		return p, fmt.Errorf("%w: invalid process BOOLEAN", ErrProtocol)
	}
	p.Split = b[16] != 0
	size := int(le.Uint16(b[18:]))
	if len(b) != 22+size {
		return p, fmt.Errorf("%w: process image length", ErrProtocol)
	}
	p.ImagePath, err = decodeWide(b[20 : 20+size])
	return p, err
}

func decodeEvent(b []byte) (Event, error) {
	var e Event
	if len(b) < eventHeaderSize || len(b) > eventBufferSize ||
		le.Uint64(b[8:]) != uint64(len(b)-eventHeaderSize) {
		return e, fmt.Errorf("%w: event header/length", ErrProtocol)
	}
	e.ID = EventID(le.Uint32(b))
	payload := b[eventHeaderSize:]
	var size, offset int
	var err error
	switch e.ID {
	case EventStartSplitting, EventStopSplitting:
		if len(payload) < 14 {
			return e, fmt.Errorf("%w: short splitting event", ErrProtocol)
		}
		e.PID, err = decodePID(payload)
		e.Reason = Reason(le.Uint32(payload[8:]))
		size, offset = int(le.Uint16(payload[12:])), 14
	case EventErrorStartSplitting, EventErrorStopSplitting:
		if len(payload) < 10 {
			return e, fmt.Errorf("%w: short splitting error", ErrProtocol)
		}
		e.PID, err = decodePID(payload)
		size, offset = int(le.Uint16(payload[8:])), 10
	case EventErrorMessage:
		if len(payload) < 6 {
			return e, fmt.Errorf("%w: short error message", ErrProtocol)
		}
		e.NTStatus = le.Uint32(payload)
		size, offset = int(le.Uint16(payload[4:])), 6
	default:
		e.Raw = append([]byte(nil), payload...)
		return e, nil
	}
	if err != nil {
		return e, err
	}
	if offset+size != len(payload) {
		return e, fmt.Errorf("%w: event string length", ErrProtocol)
	}
	text, err := decodeWide(payload[offset:])
	if e.ID == EventErrorMessage {
		e.Message = text
	} else {
		e.ImagePath = text
	}
	return e, err
}
