// Command tunneldemo demonstrates the split-tunnel controller with a real
// Wintun adapter and a controlled UDP tunnel peer.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }

func (values *stringList) Set(value string) error {
	if value == "" {
		return errors.New("path is empty")
	}
	*values = append(*values, value)
	return nil
}

type config struct {
	adapter      string
	peer         string
	tunnelIPv4   netip.Prefix
	tunnelIPv6   netip.Prefix
	internetIPv4 netip.Addr
	internetIPv6 netip.Addr
	routeIPv4    netip.Prefix
	routeIPv6    netip.Prefix
	exclusions   []string
	stopFile     string
	cleanupWait  time.Duration
}

func main() {
	configuration, err := parseConfig(os.Args[1:])
	if err == nil {
		err = runPlatform(configuration)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseConfig(arguments []string) (config, error) {
	var result config
	flags := flag.NewFlagSet("tunneldemo", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&result.adapter, "adapter", "Mullvad split tunnel demo", "Wintun adapter name")
	flags.StringVar(&result.peer, "peer", "", "controlled peer UDP address (required)")
	tunnelIPv4 := flags.String("tunnel-ipv4", "10.77.0.2/24", "TUN IPv4 prefix")
	tunnelIPv6 := flags.String("tunnel-ipv6", "fd00:77::2/64", "TUN IPv6 prefix")
	internetIPv4 := flags.String("internet-ipv4", "", "bypass interface IPv4 address (required)")
	internetIPv6 := flags.String("internet-ipv6", "", "bypass interface IPv6 address")
	routeIPv4 := flags.String("route-ipv4", "203.0.113.1/32", "IPv4 prefix sent to the TUN")
	routeIPv6 := flags.String("route-ipv6", "2001:db8:ffff::1/128", "IPv6 prefix sent to the TUN")
	flags.Var((*stringList)(&result.exclusions), "exclude", "absolute executable path to bypass; repeat as needed")
	flags.StringVar(&result.stopFile, "stop-file", "", "stop when this file exists (test automation)")
	flags.DurationVar(&result.cleanupWait, "cleanup-timeout", 15*time.Second, "driver reset timeout")
	if err := flags.Parse(arguments); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if result.peer == "" {
		return config{}, errors.New("-peer is required")
	}
	if len(result.exclusions) == 0 {
		return config{}, errors.New("at least one -exclude is required")
	}
	if result.cleanupWait <= 0 {
		return config{}, errors.New("-cleanup-timeout must be positive")
	}
	var err error
	if result.tunnelIPv4, err = parsePrefix(*tunnelIPv4, true, "tunnel IPv4"); err != nil {
		return config{}, err
	}
	if result.tunnelIPv6, err = parsePrefix(*tunnelIPv6, false, "tunnel IPv6"); err != nil {
		return config{}, err
	}
	if result.routeIPv4, err = parsePrefix(*routeIPv4, true, "route IPv4"); err != nil {
		return config{}, err
	}
	result.routeIPv4 = result.routeIPv4.Masked()
	if result.routeIPv6, err = parsePrefix(*routeIPv6, false, "route IPv6"); err != nil {
		return config{}, err
	}
	result.routeIPv6 = result.routeIPv6.Masked()
	if result.internetIPv4, err = parseAddress(*internetIPv4, true, "internet IPv4"); err != nil {
		return config{}, err
	}
	if *internetIPv6 != "" {
		if result.internetIPv6, err = parseAddress(*internetIPv6, false, "internet IPv6"); err != nil {
			return config{}, err
		}
	}
	return result, nil
}

func parsePrefix(value string, ipv4 bool, name string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Is4() != ipv4 || prefix.Addr().IsUnspecified() {
		return netip.Prefix{}, fmt.Errorf("invalid %s prefix %q", name, value)
	}
	return prefix, nil
}

func parseAddress(value string, ipv4 bool, name string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4() != ipv4 || address.IsUnspecified() || address.Is6() && address.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("invalid %s address %q", name, value)
	}
	return address, nil
}
