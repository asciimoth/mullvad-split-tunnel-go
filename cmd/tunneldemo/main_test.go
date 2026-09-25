package main

import "testing"

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
}

func TestParseConfigRejectsUnsafeValues(t *testing.T) {
	for _, arguments := range [][]string{
		{"-internet-ipv4", "192.0.2.2", "-exclude", `C:\x.exe`},
		{"-peer", "192.0.2.1:1", "-internet-ipv4", "192.0.2.2"},
		{"-peer", "192.0.2.1:1", "-internet-ipv4", "::1", "-exclude", `C:\x.exe`},
		{"-peer", "192.0.2.1:1", "-internet-ipv4", "192.0.2.2", "-tunnel-ipv6", "127.0.0.1/8", "-exclude", `C:\x.exe`},
	} {
		if _, err := parseConfig(arguments); err == nil {
			t.Fatalf("arguments were accepted: %v", arguments)
		}
	}
}
