//go:build windows && (amd64 || arm64)

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const dadStatePreferred = 4

var (
	iphlpapi                      = windows.NewLazySystemDLL("iphlpapi.dll")
	convertInterfaceLUIDToIndex   = iphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	initializeUnicastAddressEntry = iphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	createUnicastAddressEntry     = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	deleteUnicastAddressEntry     = iphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	initializeIPForwardEntry      = iphlpapi.NewProc("InitializeIpForwardEntry")
	createIPForwardEntry          = iphlpapi.NewProc("CreateIpForwardEntry2")
	deleteIPForwardEntry          = iphlpapi.NewProc("DeleteIpForwardEntry2")
)

type tunResources struct {
	adapter   *wintun.Adapter
	session   wintun.Session
	sessionUp bool
	addresses []windows.MibUnicastIpAddressRow
	routes    []windows.MibIpForwardRow2
	luid      uint64
	index     uint32
}

func callNetIO(name string, procedure *windows.LazyProc, arguments ...uintptr) error {
	result, _, _ := procedure.Call(arguments...)
	if result != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(result))
	}
	return nil
}

func createTUN(configuration config) (result *tunResources, err error) {
	adapter, err := wintun.CreateAdapter(configuration.adapter, "Wintun", nil)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter: %w", err)
	}
	resources := &tunResources{adapter: adapter, luid: adapter.LUID()}
	defer func() {
		if err != nil {
			err = errors.Join(err, resources.close())
		}
	}()
	if err = callNetIO("convert TUN LUID", convertInterfaceLUIDToIndex, uintptr(unsafe.Pointer(&resources.luid)), uintptr(unsafe.Pointer(&resources.index))); err != nil {
		return nil, err
	}
	if resources.session, err = adapter.StartSession(wintun.RingCapacityMin); err != nil {
		return nil, fmt.Errorf("start Wintun session: %w", err)
	}
	resources.sessionUp = true
	for _, prefix := range []netip.Prefix{configuration.tunnelIPv4, configuration.tunnelIPv6} {
		if err = resources.addAddress(prefix); err != nil {
			return nil, err
		}
	}
	for _, prefix := range []netip.Prefix{configuration.routeIPv4, configuration.routeIPv6} {
		if err = resources.addRoute(prefix); err != nil {
			return nil, err
		}
	}
	return resources, nil
}

func (resources *tunResources) addAddress(prefix netip.Prefix) error {
	var row windows.MibUnicastIpAddressRow
	_, _, _ = initializeUnicastAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := setRawAddress((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)), prefix.Addr()); err != nil {
		return err
	}
	row.InterfaceLuid = resources.luid
	row.ValidLifetime = ^uint32(0)
	row.PreferredLifetime = ^uint32(0)
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.DadState = dadStatePreferred
	if err := callNetIO("add TUN address", createUnicastAddressEntry, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	resources.addresses = append(resources.addresses, row)
	return nil
}

func (resources *tunResources) addRoute(prefix netip.Prefix) error {
	var row windows.MibIpForwardRow2
	_, _, _ = initializeIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = resources.luid
	if err := setRawAddress(&row.DestinationPrefix.Prefix, prefix.Addr()); err != nil {
		return err
	}
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	unspecified := netip.IPv6Unspecified()
	if prefix.Addr().Is4() {
		unspecified = netip.IPv4Unspecified()
	}
	if err := setRawAddress(&row.NextHop, unspecified); err != nil {
		return err
	}
	row.Metric = 1
	if err := callNetIO("add TUN route", createIPForwardEntry, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	resources.routes = append(resources.routes, row)
	return nil
}

func setRawAddress(raw *windows.RawSockaddrInet, address netip.Addr) error {
	*raw = windows.RawSockaddrInet{}
	if address.Is4() {
		value := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
		value.Family = windows.AF_INET
		value.Addr = address.As4()
		return nil
	}
	if address.Is6() && address.Zone() == "" {
		value := (*windows.RawSockaddrInet6)(unsafe.Pointer(raw))
		value.Family = windows.AF_INET6
		value.Addr = address.As16()
		return nil
	}
	return fmt.Errorf("unsupported address %s", address)
}

func (resources *tunResources) close() error {
	if resources == nil {
		return nil
	}
	var result error
	for index := len(resources.routes) - 1; index >= 0; index-- {
		if err := callNetIO("delete TUN route", deleteIPForwardEntry, uintptr(unsafe.Pointer(&resources.routes[index]))); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			result = errors.Join(result, err)
		}
	}
	resources.routes = nil
	for index := len(resources.addresses) - 1; index >= 0; index-- {
		if err := callNetIO("delete TUN address", deleteUnicastAddressEntry, uintptr(unsafe.Pointer(&resources.addresses[index]))); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			result = errors.Join(result, err)
		}
	}
	resources.addresses = nil
	if resources.adapter != nil {
		if resources.sessionUp {
			resources.session.End()
			resources.sessionUp = false
		}
		if err := resources.adapter.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("remove Wintun adapter: %w", err))
		}
		resources.adapter = nil
	}
	return result
}
