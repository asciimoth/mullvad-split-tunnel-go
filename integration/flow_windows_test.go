//go:build windows && winintegration && winflow

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

const (
	flowServiceIPv4 = "203.0.113.1:47823"
	flowServiceIPv6 = "[2001:db8:ffff::1]:47823"
	flowDNSIPv4     = "203.0.113.1:53"
	flowDNSIPv6     = "[2001:db8:ffff::1]:53"
)

type flowRequest struct {
	Operation    string `json:"operation"`
	ID           string `json:"id,omitempty"`
	Network      string `json:"network,omitempty"`
	Address      string `json:"address,omitempty"`
	LocalAddress string `json:"localAddress,omitempty"`
	Token        string `json:"token,omitempty"`
}

type flowResponse struct {
	PID       int    `json:"pid,omitempty"`
	LocalAddr string `json:"localAddr,omitempty"`
	Error     string `json:"error,omitempty"`
}

type flowObservation struct {
	Token        string `json:"token"`
	Cycle        int    `json:"cycle"`
	Phase        string `json:"phase"`
	Profile      string `json:"profile"`
	Role         string `json:"role"`
	Network      string `json:"network"`
	Flow         string `json:"flow"`
	ExpectedPath string `json:"expectedPath"`
	Outcome      string `json:"outcome"`
	LocalAddr    string `json:"localAddr,omitempty"`
}

type activeFlow struct {
	role    string
	network string
	id      string
}

type flowProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
	pid     uint32
}

func TestPacketFlowHelper(t *testing.T) {
	mode := os.Getenv("SPLIT_TUNNEL_FLOW_HELPER")
	if mode == "" {
		return
	}
	if mode == "descendant" {
		runDescendantProxy(t)
		return
	}
	runFlowClient(t)
}

func runDescendantProxy(t *testing.T) {
	child := exec.Command(os.Getenv("SPLIT_TUNNEL_FLOW_CHILD"), "-test.run=^TestPacketFlowHelper$")
	child.Env = append(os.Environ(), "SPLIT_TUNNEL_FLOW_HELPER=client")
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
}

func runFlowClient(t *testing.T) {
	connections := make(map[string]net.Conn)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	encoder := json.NewEncoder(os.Stdout)
	decoder := json.NewDecoder(os.Stdin)
	for {
		var request flowRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatal(err)
		}
		response := flowResponse{PID: os.Getpid()}
		switch request.Operation {
		case "pid":
		case "once":
			connection, err := dialFlow(request)
			if err == nil {
				response.LocalAddr = connection.LocalAddr().String()
				err = flowExchange(connection, request.Token)
				_ = connection.Close()
			}
			if err != nil {
				response.Error = err.Error()
			}
		case "open":
			connection, err := dialFlow(request)
			if err == nil {
				connections[request.ID] = connection
				response.LocalAddr = connection.LocalAddr().String()
			}
			if err != nil {
				response.Error = err.Error()
			}
		case "exchange":
			connection := connections[request.ID]
			if connection == nil {
				response.Error = "flow is not open"
				break
			}
			response.LocalAddr = connection.LocalAddr().String()
			if err := flowExchange(connection, request.Token); err != nil {
				response.Error = err.Error()
			}
		case "close":
			if connection := connections[request.ID]; connection != nil {
				_ = connection.Close()
				delete(connections, request.ID)
			}
		default:
			response.Error = "unknown operation"
		}
		if err := encoder.Encode(response); err != nil {
			t.Fatal(err)
		}
	}
}

func dialFlow(request flowRequest) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	if request.LocalAddress != "" {
		address := net.JoinHostPort(request.LocalAddress, "0")
		var err error
		switch {
		case strings.HasPrefix(request.Network, "tcp"):
			dialer.LocalAddr, err = net.ResolveTCPAddr(request.Network, address)
		case strings.HasPrefix(request.Network, "udp"):
			dialer.LocalAddr, err = net.ResolveUDPAddr(request.Network, address)
		default:
			err = fmt.Errorf("unsupported network %q", request.Network)
		}
		if err != nil {
			return nil, err
		}
	}
	return dialer.Dial(request.Network, request.Address)
}

func flowExchange(connection net.Conn, token string) error {
	if err := connection.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		return err
	}
	payload := []byte(token)
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, reply); err != nil {
		return err
	}
	if string(reply) != token {
		return fmt.Errorf("echo was %q, not %q", reply, token)
	}
	return nil
}

func startFlowProcess(t *testing.T, executable, mode, child string) *flowProcess {
	t.Helper()
	command := exec.Command(executable, "-test.run=^TestPacketFlowHelper$")
	command.Env = append(os.Environ(), "SPLIT_TUNNEL_FLOW_HELPER="+mode)
	if child != "" {
		command.Env = append(command.Env, "SPLIT_TUNNEL_FLOW_CHILD="+child)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &flowProcess{command: command, input: input, output: bufio.NewScanner(output)}
	t.Cleanup(func() {
		_ = input.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	response := process.request(t, flowRequest{Operation: "pid"})
	process.pid = uint32(response.PID)
	return process
}

func (p *flowProcess) request(t *testing.T, request flowRequest) flowResponse {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.input.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	for p.output.Scan() {
		var response flowResponse
		if json.Unmarshal(p.output.Bytes(), &response) == nil {
			return response
		}
	}
	if err := p.output.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("flow helper exited without a response")
	return flowResponse{}
}

type packetFlowTest struct {
	t            *testing.T
	session      *liveSession
	manifest     *os.File
	encoder      *json.Encoder
	sequence     atomic.Uint64
	cycle        int
	executables  map[string]string
	processes    map[string]*flowProcess
	currentPaths map[string]string
}

func newPacketFlowTest(t *testing.T) *packetFlowTest {
	t.Helper()
	artifactDirectory := os.Getenv("FLOW_ARTIFACT_DIR")
	if artifactDirectory == "" {
		t.Fatal("FLOW_ARTIFACT_DIR is not set")
	}
	if err := os.MkdirAll(artifactDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.Create(filepath.Join(artifactDirectory, "packet-flow-observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manifest.Close() })
	h := &packetFlowTest{
		t:            t,
		session:      newLiveSession(t),
		manifest:     manifest,
		encoder:      json.NewEncoder(manifest),
		executables:  make(map[string]string),
		processes:    make(map[string]*flowProcess),
		currentPaths: make(map[string]string),
	}
	h.prepareProcesses()
	return h
}

func (h *packetFlowTest) prepareProcesses() {
	if err := h.session.c.SetAddresses(context.Background(), addressesForProfile("dual-stack", "2")); err != nil {
		h.t.Fatal(err)
	}
	executable := mustExecutable(h.t)
	data, err := os.ReadFile(executable)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, role := range []string{"excluded", "parent", "descendant", "included"} {
		path := filepath.Join(h.t.TempDir(), role+".exe")
		if err := os.WriteFile(path, data, 0o700); err != nil {
			h.t.Fatal(err)
		}
		h.executables[role] = path
	}
	if err := h.session.c.SetExcludedPaths(context.Background(), []string{
		h.executables["excluded"], h.executables["parent"],
	}); err != nil {
		h.t.Fatal(err)
	}
	h.processes["excluded"] = startFlowProcess(h.t, h.executables["excluded"], "client", "")
	h.processes["descendant"] = startFlowProcess(h.t, h.executables["parent"], "descendant", h.executables["descendant"])
	h.processes["included"] = startFlowProcess(h.t, h.executables["included"], "client", "")
	for _, role := range []string{"excluded", "descendant"} {
		processStatus(h.t, h.session.c, h.processes[role].pid, true)
	}
	processStatus(h.t, h.session.c, h.processes["included"].pid, false)
}

func (h *packetFlowTest) token() string {
	return fmt.Sprintf("FLOW_%08d", h.sequence.Add(1))
}

func flowHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return host
}

type addressMode struct {
	name        string
	addresses   splittunnel.Addresses
	ipv4Path    string
	ipv6Path    string
	wfpIPv4Path string
	wfpIPv6Path string
}

func addr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func addressModes(suffix string) []addressMode {
	t4 := addr("198.18.0." + suffix)
	i4 := addr("198.18.1." + suffix)
	t6 := addr("fd00:18:0::" + suffix)
	i6 := addr("fd00:18:1::" + suffix)
	return []addressMode{
		{name: "mode-1-dual-stack", addresses: splittunnel.Addresses{TunnelIPv4: t4, InternetIPv4: i4, TunnelIPv6: t6, InternetIPv6: i6}, ipv4Path: "underlay", ipv6Path: "underlay", wfpIPv4Path: "underlay", wfpIPv6Path: "underlay"},
		{name: "mode-2-ipv4-only", addresses: splittunnel.Addresses{TunnelIPv4: t4, InternetIPv4: i4}, ipv4Path: "underlay", ipv6Path: "tunnel", wfpIPv4Path: "underlay", wfpIPv6Path: "none"},
		{name: "mode-3-ipv4-internet-ipv6", addresses: splittunnel.Addresses{TunnelIPv4: t4, InternetIPv4: i4, InternetIPv6: i6}, ipv4Path: "underlay", ipv6Path: "tunnel", wfpIPv4Path: "underlay", wfpIPv6Path: "tunnel"},
		{name: "mode-4-ipv4-tunnel-ipv6", addresses: splittunnel.Addresses{TunnelIPv4: t4, InternetIPv4: i4, TunnelIPv6: t6}, ipv4Path: "underlay", ipv6Path: "none", wfpIPv4Path: "underlay", wfpIPv6Path: "none"},
		{name: "mode-5-ipv6-only", addresses: splittunnel.Addresses{TunnelIPv6: t6, InternetIPv6: i6}, ipv4Path: "tunnel", ipv6Path: "underlay", wfpIPv4Path: "none", wfpIPv6Path: "underlay"},
		{name: "mode-6-internet-ipv4-ipv6", addresses: splittunnel.Addresses{InternetIPv4: i4, TunnelIPv6: t6, InternetIPv6: i6}, ipv4Path: "tunnel", ipv6Path: "underlay", wfpIPv4Path: "tunnel", wfpIPv6Path: "underlay"},
		{name: "mode-7-tunnel-ipv4-ipv6", addresses: splittunnel.Addresses{TunnelIPv4: t4, TunnelIPv6: t6, InternetIPv6: i6}, ipv4Path: "none", ipv6Path: "underlay", wfpIPv4Path: "none", wfpIPv6Path: "underlay"},
		{name: "mode-8-tunnel-ipv4-internet-ipv6", addresses: splittunnel.Addresses{TunnelIPv4: t4, InternetIPv6: i6}, ipv4Path: "none", ipv6Path: "tunnel", wfpIPv4Path: "none", wfpIPv6Path: "tunnel"},
		{name: "mode-9-internet-ipv4-tunnel-ipv6", addresses: splittunnel.Addresses{InternetIPv4: i4, TunnelIPv6: t6}, ipv4Path: "tunnel", ipv6Path: "none", wfpIPv4Path: "tunnel", wfpIPv6Path: "none"},
	}
}

func TestPacketFlowPolicyTable(t *testing.T) {
	want := []struct {
		name         string
		availability string
		paths        [4]string
	}{
		{name: "mode-1-dual-stack", availability: "1111", paths: [4]string{"underlay", "underlay", "underlay", "underlay"}},
		{name: "mode-2-ipv4-only", availability: "1100", paths: [4]string{"underlay", "tunnel", "underlay", "none"}},
		{name: "mode-3-ipv4-internet-ipv6", availability: "1110", paths: [4]string{"underlay", "tunnel", "underlay", "tunnel"}},
		{name: "mode-4-ipv4-tunnel-ipv6", availability: "1101", paths: [4]string{"underlay", "none", "underlay", "none"}},
		{name: "mode-5-ipv6-only", availability: "0011", paths: [4]string{"tunnel", "underlay", "none", "underlay"}},
		{name: "mode-6-internet-ipv4-ipv6", availability: "1011", paths: [4]string{"tunnel", "underlay", "tunnel", "underlay"}},
		{name: "mode-7-tunnel-ipv4-ipv6", availability: "0111", paths: [4]string{"none", "underlay", "none", "underlay"}},
		{name: "mode-8-tunnel-ipv4-internet-ipv6", availability: "0110", paths: [4]string{"none", "tunnel", "none", "tunnel"}},
		{name: "mode-9-internet-ipv4-tunnel-ipv6", availability: "1001", paths: [4]string{"tunnel", "none", "tunnel", "none"}},
	}
	modes := addressModes("2")
	if len(modes) != len(want) {
		t.Fatalf("address mode count = %d; want %d", len(modes), len(want))
	}
	for i, mode := range modes {
		availability := ""
		for _, address := range []netip.Addr{
			mode.addresses.InternetIPv4, mode.addresses.TunnelIPv4,
			mode.addresses.InternetIPv6, mode.addresses.TunnelIPv6,
		} {
			if address.IsValid() {
				availability += "1"
			} else {
				availability += "0"
			}
		}
		paths := [4]string{mode.ipv4Path, mode.ipv6Path, mode.wfpIPv4Path, mode.wfpIPv6Path}
		if mode.name != want[i].name || availability != want[i].availability || paths != want[i].paths {
			t.Errorf("mode %d = %q %s %v; want %q %s %v", i+1, mode.name, availability, paths, want[i].name, want[i].availability, want[i].paths)
		}
		for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			if path := expectedFlowPath(mode, "included", network); path != "tunnel" {
				t.Errorf("%s included %s path = %s; want tunnel", mode.name, network, path)
			}
			if path := expectedWFPPath(mode, "included", network); path != "none" {
				t.Errorf("%s filtered included %s path = %s; want none", mode.name, network, path)
			}
		}
	}
}

func TestPacketFlowValidateResponse(t *testing.T) {
	for _, test := range []struct {
		name         string
		expectedPath string
		network      string
		response     flowResponse
		wantError    string
	}{
		{name: "IPv4 tunnel", expectedPath: "tunnel", network: "tcp4", response: flowResponse{LocalAddr: "198.18.0.2:1234"}},
		{name: "IPv4 underlay", expectedPath: "underlay", network: "udp4", response: flowResponse{LocalAddr: "198.18.1.2:1234"}},
		{name: "IPv6 tunnel", expectedPath: "tunnel", network: "tcp6", response: flowResponse{LocalAddr: "[fd00:18::2]:1234"}},
		{name: "IPv6 underlay", expectedPath: "underlay", network: "udp6", response: flowResponse{LocalAddr: "[fd00:18:1::2]:1234"}},
		{name: "none stopped", expectedPath: "none", network: "tcp4", response: flowResponse{Error: "stopped"}},
		{name: "optional tunnel stopped", expectedPath: "tunnel-or-none-stopped", network: "tcp4", response: flowResponse{Error: "stopped"}},
		{name: "optional tunnel survived", expectedPath: "tunnel-or-none-stopped", network: "tcp6", response: flowResponse{LocalAddr: "[fd00:18::2]:1234"}},
		{name: "optional underlay stopped", expectedPath: "underlay-or-none-stopped", network: "udp4", response: flowResponse{Error: "stopped"}},
		{name: "optional underlay survived", expectedPath: "underlay-or-none-stopped", network: "udp6", response: flowResponse{LocalAddr: "[fd00:18:1::2]:1234"}},
		{name: "none survived", expectedPath: "none", network: "tcp4", response: flowResponse{LocalAddr: "198.18.0.2:1234"}, wantError: "unexpectedly survived"},
		{name: "required tunnel stopped", expectedPath: "tunnel", network: "tcp4", response: flowResponse{Error: "stopped"}, wantError: "stopped"},
		{name: "optional tunnel used underlay", expectedPath: "tunnel-or-none-stopped", network: "tcp4", response: flowResponse{LocalAddr: "198.18.1.2:1234"}, wantError: "local address"},
		{name: "optional underlay used tunnel", expectedPath: "underlay-or-none-stopped", network: "tcp4", response: flowResponse{LocalAddr: "198.18.0.2:1234"}, wantError: "local address"},
		{name: "unknown path", expectedPath: "elsewhere", network: "tcp4", response: flowResponse{Error: "stopped"}, wantError: "unknown expected path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateFlowResponse(test.expectedPath, test.network, "2", test.response)
			if test.wantError == "" && err != nil {
				t.Fatalf("validateFlowResponse() error = %v; want nil", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("validateFlowResponse() error = %v; want text %q", err, test.wantError)
			}
		})
	}
}

func expectedFlowPath(mode addressMode, role, network string) string {
	if role == "included" {
		return "tunnel"
	}
	if strings.HasSuffix(network, "4") {
		return mode.ipv4Path
	}
	return mode.ipv6Path
}

func expectedWFPPath(mode addressMode, role, network string) string {
	if role == "included" {
		return "none"
	}
	if strings.HasSuffix(network, "4") {
		return mode.wfpIPv4Path
	}
	return mode.wfpIPv6Path
}

func expectedFlowAddress(path, network, suffix string) string {
	var address string
	if strings.HasSuffix(network, "4") {
		if path == "underlay" {
			address = "198.18.1." + suffix
		} else {
			address = "198.18.0." + suffix
		}
	} else if path == "underlay" {
		address = "fd00:18:1::" + suffix
	} else {
		address = "fd00:18:0::" + suffix
	}
	return netip.MustParseAddr(address).String()
}

func flowRemote(network string) string {
	if strings.HasSuffix(network, "4") {
		return flowServiceIPv4
	}
	return flowServiceIPv6
}

func flowDNSRemote(network string) string {
	if strings.HasSuffix(network, "4") {
		return flowDNSIPv4
	}
	return flowDNSIPv6
}

func (h *packetFlowTest) observe(phase, profile, role, network, flow, expectedPath, expectedSuffix string, response flowResponse) {
	h.t.Helper()
	outcome := "echo"
	if response.Error != "" {
		outcome = "stopped"
	}
	observation := flowObservation{
		Token: h.currentPaths[flow], Cycle: h.cycle, Phase: phase, Profile: profile,
		Role: role, Network: network, Flow: flow, ExpectedPath: expectedPath,
		Outcome: outcome, LocalAddr: response.LocalAddr,
	}
	if err := h.encoder.Encode(observation); err != nil {
		h.t.Fatal(err)
	}
	if err := h.manifest.Sync(); err != nil {
		h.t.Fatal(err)
	}
	if err := validateFlowResponse(expectedPath, network, expectedSuffix, response); err != nil {
		h.t.Fatalf("%s: %v", flow, err)
	}
}

func validateFlowResponse(expectedPath, network, expectedSuffix string, response flowResponse) error {
	addressPath := expectedPath
	optionalStop := false
	switch expectedPath {
	case "tunnel", "underlay":
	case "none":
		if response.Error == "" {
			return errors.New("existing flow unexpectedly survived")
		}
		return nil
	case "tunnel-or-none-stopped":
		addressPath = "tunnel"
		optionalStop = true
	case "underlay-or-none-stopped":
		addressPath = "underlay"
		optionalStop = true
	default:
		return fmt.Errorf("unknown expected path %q", expectedPath)
	}
	if optionalStop && response.Error != "" {
		return nil
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	if host := flowHost(response.LocalAddr); host != expectedFlowAddress(addressPath, network, expectedSuffix) {
		return fmt.Errorf("used local address %q; want %s path address", host, expectedPath)
	}
	return nil
}

func (h *packetFlowTest) exchange(phase, profile, role, network, id, expectedPath, suffix string) {
	h.t.Helper()
	token := h.token()
	h.currentPaths[id] = token
	// WFP invalidation and TCP teardown can lag the process-policy event on a
	// busy VM. Keep testing for convergence instead of failing on scheduling
	// delay. The packet evidence still rejects traffic on the opposite path.
	stopDeadline := time.Now().Add(15 * time.Second)
	for {
		response := h.processes[role].request(h.t, flowRequest{
			Operation: "exchange", ID: id, Token: token,
		})
		if response.Error != "" || !strings.HasSuffix(expectedPath, "-stopped") || time.Now().After(stopDeadline) {
			h.observe(phase, profile, role, network, id, expectedPath, suffix, response)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *packetFlowTest) open(phase, profile, role, network, id, expectedPath, suffix string) {
	h.t.Helper()
	response := h.processes[role].request(h.t, flowRequest{
		Operation: "open", ID: id, Network: network, Address: flowRemote(network),
	})
	if response.Error != "" {
		h.t.Fatalf("open %s: %s", id, response.Error)
	}
	if host := flowHost(response.LocalAddr); host != expectedFlowAddress(expectedPath, network, suffix) {
		h.t.Fatalf("open %s used local address %q; want %s path address", id, host, expectedPath)
	}
}

func (h *packetFlowTest) close(role, id string) {
	h.processes[role].request(h.t, flowRequest{Operation: "close", ID: id})
}

func (h *packetFlowTest) once(phase, profile, role, network, kind, expectedPath, suffix string) {
	h.onceRemote(phase, profile, role, network, kind, expectedPath, suffix, flowRemote(network))
}

func (h *packetFlowTest) onceRemote(phase, profile, role, network, kind, expectedPath, suffix, remote string) {
	h.t.Helper()
	token := h.token()
	id := strings.Join([]string{phase, profile, role, network, kind, token}, "/")
	h.currentPaths[id] = token
	response := h.processes[role].request(h.t, flowRequest{
		Operation: "once", Network: network, Address: remote, Token: token,
	})
	h.observe(phase, profile, role, network, id, expectedPath, suffix, response)
}

func (h *packetFlowTest) onceBound(
	phase, role, network, localAddress, expectedPath string,
) {
	h.t.Helper()
	token := h.token()
	id := strings.Join([]string{phase, role, network, token}, "/")
	h.currentPaths[id] = token
	response := h.processes[role].request(h.t, flowRequest{
		Operation: "once", Network: network, Address: flowRemote(network),
		LocalAddress: localAddress, Token: token,
	})
	h.observe(phase, "dual-stack", role, network, id, expectedPath, "2", response)
}

func addressesForProfile(profile, suffix string) splittunnel.Addresses {
	for _, mode := range addressModes(suffix) {
		if mode.name == profile || profile == "dual-stack" && mode.name == "mode-1-dual-stack" {
			return mode.addresses
		}
	}
	panic("unknown address profile: " + profile)
}

func (h *packetFlowTest) setProfile(profile, suffix string) {
	h.t.Helper()
	if err := h.session.c.SetAddresses(context.Background(), addressesForProfile(profile, suffix)); err != nil {
		h.t.Fatal(err)
	}
}

func (h *packetFlowTest) setExclusions(roles ...string) {
	h.t.Helper()
	paths := make([]string, 0, len(roles))
	for _, role := range roles {
		paths = append(paths, h.executables[role])
	}
	if err := h.session.c.SetExcludedPaths(context.Background(), paths); err != nil {
		h.t.Fatal(err)
	}
}

func (h *packetFlowTest) waitRoles(excludedRoles ...string) {
	h.t.Helper()
	excluded := make(map[string]bool, len(excludedRoles))
	for _, role := range excludedRoles {
		excluded[role] = true
	}
	for _, role := range []string{"excluded", "descendant", "included"} {
		processStatus(h.t, h.session.c, h.processes[role].pid, excluded[role])
	}
}

func (h *packetFlowTest) openActiveFlows(phase string, paths map[string]string, suffix string) []activeFlow {
	h.t.Helper()
	flows := make([]activeFlow, 0, 12)
	for _, role := range []string{"excluded", "descendant", "included"} {
		for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
			id := strings.Join([]string{phase, strconv.Itoa(h.cycle), role, network}, "/")
			h.open(phase, "dual-stack", role, network, id, paths[role], suffix)
			h.exchange(phase+"-initial", "dual-stack", role, network, id, paths[role], suffix)
			flows = append(flows, activeFlow{role: role, network: network, id: id})
		}
	}
	return flows
}

func (h *packetFlowTest) closeActiveFlows(flows []activeFlow) {
	for _, flow := range flows {
		h.close(flow.role, flow.id)
	}
}

func (h *packetFlowTest) exchangeActiveFlows(phase string, flows []activeFlow, paths map[string]string, suffix string) {
	h.t.Helper()
	for _, flow := range flows {
		h.exchange(phase, "dual-stack", flow.role, flow.network, flow.id, paths[flow.role], suffix)
	}
}

func (h *packetFlowTest) runExclusionChanges() {
	h.setProfile("dual-stack", "2")
	h.setExclusions()
	h.waitRoles()
	flows := h.openActiveFlows("before-add", map[string]string{
		"excluded": "tunnel", "descendant": "tunnel", "included": "tunnel",
	}, "2")

	h.setExclusions("excluded", "parent")
	h.waitRoles("excluded", "descendant")
	h.exchangeActiveFlows("after-add-existing", flows, map[string]string{
		"excluded": "tunnel-or-none-stopped", "descendant": "tunnel-or-none-stopped", "included": "tunnel",
	}, "2")
	h.closeActiveFlows(flows)
	flows = h.openActiveFlows("after-add-new", map[string]string{
		"excluded": "underlay", "descendant": "underlay", "included": "tunnel",
	}, "2")

	h.setExclusions("included")
	h.waitRoles("included")
	h.exchangeActiveFlows("after-replace-existing", flows, map[string]string{
		"excluded": "underlay", "descendant": "underlay", "included": "tunnel-or-none-stopped",
	}, "2")
	h.closeActiveFlows(flows)
	flows = h.openActiveFlows("after-replace-new", map[string]string{
		"excluded": "tunnel", "descendant": "tunnel", "included": "underlay",
	}, "2")

	h.setExclusions()
	h.waitRoles()
	h.exchangeActiveFlows("after-clear-existing", flows, map[string]string{
		"excluded": "tunnel", "descendant": "tunnel", "included": "underlay",
	}, "2")
	h.closeActiveFlows(flows)
	flows = h.openActiveFlows("after-clear-new", map[string]string{
		"excluded": "tunnel", "descendant": "tunnel", "included": "tunnel",
	}, "2")
	h.closeActiveFlows(flows)
}

func (h *packetFlowTest) runExplicitBinds() {
	h.setProfile("dual-stack", "2")
	h.setExclusions("excluded", "parent")
	h.waitRoles("excluded", "descendant")
	for _, role := range []string{"excluded", "descendant"} {
		for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			h.onceBound("explicit-tunnel-bind", role, network,
				expectedFlowAddress("tunnel", network, "2"), "underlay")
			h.onceBound("explicit-underlay-bind", role, network,
				expectedFlowAddress("underlay", network, "2"), "underlay")
		}
	}
}

func (h *packetFlowTest) runLocalhostBinds() {
	h.setProfile("dual-stack", "2")
	if err := h.session.c.SetExcludedPaths(context.Background(), []string{mustExecutable(h.t)}); err != nil {
		h.t.Fatal(err)
	}
	processStatus(h.t, h.session.c, uint32(os.Getpid()), true)

	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		host := "127.0.0.1"
		if strings.HasSuffix(network, "6") {
			host = "::1"
		}
		token := h.token()
		address, stop, serverDone := startLoopbackEcho(h.t, network, host, token)
		processStatus(h.t, h.session.c, h.processes["included"].pid, true)
		response := h.processes["included"].request(h.t, flowRequest{
			Operation: "once", Network: network, Address: address,
			LocalAddress: host, Token: token,
		})
		var serverErr error
		select {
		case serverErr = <-serverDone:
		case <-time.After(6 * time.Second):
			stop()
			serverErr = <-serverDone
			if serverErr == nil {
				serverErr = errors.New("echo server timed out")
			}
		}
		stop()
		if serverErr != nil {
			h.t.Fatalf("%s loopback echo: %v; client: %s", network, serverErr, response.Error)
		}
		if response.Error != "" {
			h.t.Fatalf("%s loopback client: %s", network, response.Error)
		}
		if localHost := flowHost(response.LocalAddr); localHost != host {
			h.t.Fatalf("%s loopback client used %q; want %s", network, localHost, host)
		}
	}
}

func startLoopbackEcho(
	t *testing.T, network, host, token string,
) (address string, stop func(), done <-chan error) {
	t.Helper()
	result := make(chan error, 1)
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatalf("listen on %s loopback: %v", network, err)
		}
		if boundHost := flowHost(listener.Addr().String()); boundHost != host {
			_ = listener.Close()
			t.Fatalf("%s loopback bind was redirected to %q", network, boundHost)
		}
		go func() {
			connection, err := listener.Accept()
			if err == nil {
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				payload := make([]byte, len(token))
				_, err = io.ReadFull(connection, payload)
				if err == nil && string(payload) != token {
					err = fmt.Errorf("received %q, want %q", payload, token)
				}
				if err == nil {
					_, err = connection.Write(payload)
				}
				_ = connection.Close()
			}
			result <- err
		}()
		return listener.Addr().String(), func() { _ = listener.Close() }, result
	}

	connection, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen on %s loopback: %v", network, err)
	}
	if boundHost := flowHost(connection.LocalAddr().String()); boundHost != host {
		_ = connection.Close()
		t.Fatalf("%s loopback bind was redirected to %q", network, boundHost)
	}
	go func() {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, len(token))
		n, peer, err := connection.ReadFrom(payload)
		if err == nil && string(payload[:n]) != token {
			err = fmt.Errorf("received %q, want %q", payload[:n], token)
		}
		if err == nil {
			_, err = connection.WriteTo(payload[:n], peer)
		}
		result <- err
	}()
	return connection.LocalAddr().String(), func() { _ = connection.Close() }, result
}

func runAddressCommand(t *testing.T, script string) {
	t.Helper()
	command := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("change flow addresses: %v\n%s", err, output)
	}
}

func addClientAddresses(t *testing.T, suffix string) {
	t.Helper()
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$t=Get-NetAdapter|Where-Object MacAddress -eq '52-54-00-12-34-10'
$u=Get-NetAdapter|Where-Object MacAddress -eq '52-54-00-12-34-11'
New-NetIPAddress -InterfaceIndex $t.ifIndex -IPAddress '198.18.0.%[1]s' -PrefixLength 24|Out-Null
New-NetIPAddress -InterfaceIndex $u.ifIndex -IPAddress '198.18.1.%[1]s' -PrefixLength 24|Out-Null
New-NetIPAddress -InterfaceIndex $t.ifIndex -IPAddress 'fd00:18::%[1]s' -PrefixLength 64|Out-Null
New-NetIPAddress -InterfaceIndex $u.ifIndex -IPAddress 'fd00:18:1::%[1]s' -PrefixLength 64|Out-Null
$expected=@('198.18.0.%[1]s','198.18.1.%[1]s','fd00:18::%[1]s','fd00:18:1::%[1]s')
$deadline=(Get-Date).AddSeconds(15)
do {
    $ready=@(Get-NetIPAddress|Where-Object { $_.IPAddress -in $expected -and $_.AddressState -eq 'Preferred' })
    if ($ready.Count -eq $expected.Count) { break }
    if ((Get-Date) -ge $deadline) { throw "Addresses did not become preferred: $($expected -join ', ')" }
    Start-Sleep -Milliseconds 100
} while ($true)
`, suffix)
	runAddressCommand(t, script)
}

func removeClientAddresses(t *testing.T, suffix string) {
	t.Helper()
	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$t=Get-NetAdapter|Where-Object MacAddress -eq '52-54-00-12-34-10'
$u=Get-NetAdapter|Where-Object MacAddress -eq '52-54-00-12-34-11'
Remove-NetIPAddress -InterfaceIndex $t.ifIndex -IPAddress '198.18.0.%[1]s' -Confirm:$false
Remove-NetIPAddress -InterfaceIndex $u.ifIndex -IPAddress '198.18.1.%[1]s' -Confirm:$false
Remove-NetIPAddress -InterfaceIndex $t.ifIndex -IPAddress 'fd00:18::%[1]s' -Confirm:$false
Remove-NetIPAddress -InterfaceIndex $u.ifIndex -IPAddress 'fd00:18:1::%[1]s' -Confirm:$false
$removed=@('198.18.0.%[1]s','198.18.1.%[1]s','fd00:18::%[1]s','fd00:18:1::%[1]s')
$deadline=(Get-Date).AddSeconds(15)
do {
    $remaining=@(Get-NetIPAddress|Where-Object { $_.IPAddress -in $removed })
    if ($remaining.Count -eq 0) { break }
    if ((Get-Date) -ge $deadline) { throw "Addresses were not removed: $($removed -join ', ')" }
    Start-Sleep -Milliseconds 100
} while ($true)
`, suffix)
	runAddressCommand(t, script)
}

func (h *packetFlowTest) replaceAddresses(from, to string) {
	h.t.Helper()
	addClientAddresses(h.t, to)
	h.setProfile("dual-stack", to)
	removeClientAddresses(h.t, from)
}

func (h *packetFlowTest) runAddressChanges() {
	h.setExclusions("excluded", "parent")
	h.waitRoles("excluded", "descendant")
	h.setProfile("dual-stack", "2")
	flows := h.openActiveFlows("before-address-replace", map[string]string{
		"excluded": "underlay", "descendant": "underlay", "included": "tunnel",
	}, "2")
	h.replaceAddresses("2", "3")
	h.exchangeActiveFlows("after-address-replace-existing", flows, map[string]string{
		"excluded": "underlay-or-none-stopped", "descendant": "underlay-or-none-stopped", "included": "tunnel-or-none-stopped",
	}, "2")
	h.closeActiveFlows(flows)
	flows = h.openActiveFlows("after-address-replace-new", map[string]string{
		"excluded": "underlay", "descendant": "underlay", "included": "tunnel",
	}, "3")
	h.closeActiveFlows(flows)
	h.replaceAddresses("3", "2")
}

func (h *packetFlowTest) runMatrix() {
	for _, mode := range addressModes("2") {
		if err := h.session.c.SetAddresses(context.Background(), mode.addresses); err != nil {
			h.t.Fatal(err)
		}
		h.setExclusions("excluded", "parent")
		for _, role := range []string{"excluded", "descendant", "included"} {
			for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				path := expectedFlowPath(mode, role, network)
				h.once("new", mode.name, role, network, "request-response", path, "2")
				if path == "none" {
					h.once("stream", mode.name, role, network, "long-lived-blocked", path, "2")
					continue
				}
				id := strings.Join([]string{"stream", strconv.Itoa(h.cycle), mode.name, role, network}, "/")
				h.open("stream", mode.name, role, network, id, path, "2")
				for range 3 {
					h.exchange("stream", mode.name, role, network, id, path, "2")
				}
				h.close(role, id)
			}
		}
	}
}

func (h *packetFlowTest) runWFPInteraction() {
	h.setExclusions("excluded", "parent")
	h.waitRoles("excluded", "descendant")
	for sublayer, test := range []struct {
		name   string
		port   uint16
		remote func(string) string
	}{
		{name: "baseline-sublayer", port: 47823, remote: flowRemote},
		{name: "dns-sublayer", port: 53, remote: flowDNSRemote},
	} {
		keys, err := h.session.fixture.addRestrictiveFilters(sublayer, test.port)
		if err != nil {
			h.t.Fatalf("add %s filters: %v", test.name, err)
		}
		for _, mode := range addressModes("2") {
			if err := h.session.c.SetAddresses(context.Background(), mode.addresses); err != nil {
				h.t.Fatal(err)
			}
			for _, role := range []string{"excluded", "descendant", "included"} {
				for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
					path := expectedWFPPath(mode, role, network)
					profile := test.name + "/" + mode.name
					h.onceRemote("wfp", profile, role, network, "restrictive-filter", path, "2", test.remote(network))
				}
			}
		}
		if err := h.session.fixture.removeFilters(keys); err != nil {
			h.t.Fatalf("remove %s filters: %v", test.name, err)
		}
	}
	h.setProfile("dual-stack", "2")
}

func (h *packetFlowTest) reinitialize() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.session.c.Reset(ctx); err != nil {
		h.t.Fatal(err)
	}
	if err := h.session.c.Initialize(ctx, splittunnel.Sublayers{
		Baseline: driverGUID(h.t, h.session.fixture.keys[0].String()),
		DNS:      driverGUID(h.t, h.session.fixture.keys[1].String()),
	}); err != nil {
		h.t.Fatal(err)
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.session.c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		h.t.Fatal(err)
	}
}

func TestPacketFlowCharacterization(t *testing.T) {
	h := newPacketFlowTest(t)
	for cycle := 1; cycle <= 2; cycle++ {
		h.cycle = cycle
		h.runMatrix()
		h.runWFPInteraction()
		h.runExclusionChanges()
		h.runExplicitBinds()
		h.runLocalhostBinds()
		h.runAddressChanges()
		if cycle == 1 {
			h.reinitialize()
		}
	}
}
