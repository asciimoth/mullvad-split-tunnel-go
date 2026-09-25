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
)

type flowRequest struct {
	Operation string `json:"operation"`
	ID        string `json:"id,omitempty"`
	Network   string `json:"network,omitempty"`
	Address   string `json:"address,omitempty"`
	Token     string `json:"token,omitempty"`
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
			connection, err := net.DialTimeout(request.Network, request.Address, 3*time.Second)
			if err == nil {
				response.LocalAddr = connection.LocalAddr().String()
				err = flowExchange(connection, request.Token)
				_ = connection.Close()
			}
			if err != nil {
				response.Error = err.Error()
			}
		case "open":
			connection, err := net.DialTimeout(request.Network, request.Address, 3*time.Second)
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

func expectedFlowPath(profile, role, network string) string {
	if role == "included" {
		return "tunnel"
	}
	if strings.HasSuffix(network, "4") && profile == "ipv6-only" {
		return "tunnel"
	}
	if strings.HasSuffix(network, "6") && profile == "ipv4-only" {
		return "tunnel"
	}
	return "underlay"
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
	stopped := strings.HasSuffix(expectedPath, "-stopped")
	addressPath := strings.TrimSuffix(expectedPath, "-or-none-stopped")
	addressPath = strings.TrimSuffix(addressPath, "-stopped")
	if expectedPath == "none" {
		if response.Error == "" {
			h.t.Fatalf("%s: existing flow unexpectedly survived", flow)
		}
		return
	}
	if stopped {
		if response.Error == "" {
			h.t.Fatalf("%s: existing flow unexpectedly survived", flow)
		}
		return
	}
	if response.Error != "" {
		h.t.Fatalf("%s: %s", flow, response.Error)
	}
	if host := flowHost(response.LocalAddr); host != expectedFlowAddress(addressPath, network, expectedSuffix) {
		h.t.Fatalf("%s used local address %q; want %s path address", flow, host, expectedPath)
	}
}

func (h *packetFlowTest) exchange(phase, profile, role, network, id, expectedPath, suffix string) {
	h.t.Helper()
	token := h.token()
	h.currentPaths[id] = token
	response := h.processes[role].request(h.t, flowRequest{
		Operation: "exchange", ID: id, Token: token,
	})
	h.observe(phase, profile, role, network, id, expectedPath, suffix, response)
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
	h.t.Helper()
	token := h.token()
	id := strings.Join([]string{phase, profile, role, network, kind, token}, "/")
	h.currentPaths[id] = token
	response := h.processes[role].request(h.t, flowRequest{
		Operation: "once", Network: network, Address: flowRemote(network), Token: token,
	})
	h.observe(phase, profile, role, network, id, expectedPath, suffix, response)
}

func addressesForProfile(profile, suffix string) splittunnel.Addresses {
	var addresses splittunnel.Addresses
	if profile != "ipv6-only" {
		addresses.TunnelIPv4 = netip.MustParseAddr("198.18.0." + suffix)
		addresses.InternetIPv4 = netip.MustParseAddr("198.18.1." + suffix)
	}
	if profile != "ipv4-only" {
		addresses.TunnelIPv6 = netip.MustParseAddr("fd00:18:0::" + suffix)
		addresses.InternetIPv6 = netip.MustParseAddr("fd00:18:1::" + suffix)
	}
	return addresses
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
Start-Sleep -Seconds 2
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
	for _, profile := range []string{"dual-stack", "ipv4-only", "ipv6-only"} {
		h.setProfile(profile, "2")
		h.setExclusions("excluded", "parent")
		for _, role := range []string{"excluded", "descendant", "included"} {
			for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				path := expectedFlowPath(profile, role, network)
				h.once("new", profile, role, network, "request-response", path, "2")
				id := strings.Join([]string{"stream", strconv.Itoa(h.cycle), profile, role, network}, "/")
				h.open("stream", profile, role, network, id, path, "2")
				for range 3 {
					h.exchange("stream", profile, role, network, id, path, "2")
				}
				h.close(role, id)
			}
		}
	}
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
		h.runExclusionChanges()
		h.runAddressChanges()
		if cycle == 1 {
			h.reinitialize()
		}
	}
}
