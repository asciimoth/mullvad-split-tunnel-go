package main

import (
	"reflect"
	"testing"
	"time"
)

func TestParseConfig(t *testing.T) {
	configuration, err := parseConfig([]string{
		"-peer", "192.0.2.1:51900",
		"-internet-ipv4", "192.0.2.2",
		"-internet-ipv6", "2001:db8::2",
		"-exclude", `C:\demo\excluded.exe`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.tunnelIPv4.Addr().Is4() || !configuration.tunnelIPv6.Addr().Is6() {
		t.Fatalf("unexpected tunnel prefixes: %v, %v", configuration.tunnelIPv4, configuration.tunnelIPv6)
	}
	if configuration.routeIPv4.String() != "203.0.113.1/32" ||
		configuration.routeIPv6.String() != "2001:db8:ffff::1/128" {
		t.Fatalf("unexpected routes: %v, %v", configuration.routeIPv4, configuration.routeIPv6)
	}
	if !reflect.DeepEqual(configuration.exclusions, []string{`C:\demo\excluded.exe`}) {
		t.Fatalf("unexpected exclusions: %q", configuration.exclusions)
	}
}

func TestParseConfigRejectsUnsafeValues(t *testing.T) {
	base := []string{"-peer", "192.0.2.1:1", "-internet-ipv4", "192.0.2.2", "-exclude", `C:\x.exe`}
	cases := map[string][]string{
		"missing peer":          {"-internet-ipv4", "192.0.2.2", "-exclude", `C:\x.exe`},
		"missing exclusion":     {"-peer", "192.0.2.1:1", "-internet-ipv4", "192.0.2.2"},
		"wrong Internet family": {"-peer", "192.0.2.1:1", "-internet-ipv4", "::1", "-exclude", `C:\x.exe`},
		"wrong tunnel family":   append(append([]string{}, base...), "-tunnel-ipv6", "127.0.0.1/8"),
		"wrong route family":    append(append([]string{}, base...), "-route-ipv4", "2001:db8::/64"),
		"unspecified prefix":    append(append([]string{}, base...), "-tunnel-ipv4", "0.0.0.0/0"),
		"link-local IPv6":       append(append([]string{}, base...), "-internet-ipv6", "fe80::1"),
		"nonpositive timeout":   append(append([]string{}, base...), "-cleanup-timeout", "0s"),
		"extra argument":        append(append([]string{}, base...), "extra"),
		"empty exclusion":       append(append([]string{}, base[:4]...), "-exclude", ""),
		"invalid flag":          append(append([]string{}, base...), "-unknown"),
	}
	for name, arguments := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(arguments); err == nil {
				t.Fatalf("arguments were accepted: %v", arguments)
			}
		})
	}
}

func TestStringList(t *testing.T) {
	values := stringList{"one"}
	if got := values.String(); got != "[one]" {
		t.Fatalf("String() = %q", got)
	}
	if err := values.Set("two"); err != nil || !reflect.DeepEqual(values, stringList{"one", "two"}) {
		t.Fatalf("Set(two) = %q, %v", values, err)
	}
	if err := values.Set(""); err == nil {
		t.Fatal("empty value was accepted")
	}
}

func TestParseConfigMasksRoutePrefixes(t *testing.T) {
	configuration, err := parseConfig([]string{
		"-peer", "192.0.2.1:1", "-internet-ipv4", "192.0.2.2",
		"-exclude", `C:\x.exe`, "-route-ipv4", "203.0.113.99/24",
		"-route-ipv6", "2001:db8:ffff::99/64", "-cleanup-timeout", time.Second.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.routeIPv4.String() != "203.0.113.0/24" ||
		configuration.routeIPv6.String() != "2001:db8:ffff::/64" {
		t.Fatalf("routes were not masked: %v, %v", configuration.routeIPv4, configuration.routeIPv6)
	}
}
