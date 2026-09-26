//go:build windows && winintegration && winflow

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

func TestPacketFlowTunnelDemo(t *testing.T) {
	demoExecutable := os.Getenv("TUNNELDEMO_EXE")
	if demoExecutable == "" {
		t.Fatal("TUNNELDEMO_EXE is not set")
	}
	artifactDirectory := os.Getenv("FLOW_ARTIFACT_DIR")
	if artifactDirectory == "" {
		t.Fatal("FLOW_ARTIFACT_DIR is not set")
	}
	executable := mustExecutable(t)
	roles := make(map[string]string)
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"excluded", "parent", "descendant", "included"} {
		path := filepath.Join(t.TempDir(), "tunneldemo-"+role+".exe")
		if err := os.WriteFile(path, data, 0o700); err != nil {
			t.Fatal(err)
		}
		roles[role] = path
	}
	stopFile := filepath.Join(t.TempDir(), "stop")
	logPath := filepath.Join(artifactDirectory, "tunneldemo.log")
	command := exec.Command(demoExecutable,
		"-peer", "198.18.0.1:51900",
		"-internet-ipv4", "198.18.1.2",
		"-internet-ipv6", "fd00:18:1::2",
		"-exclude", roles["excluded"],
		"-exclude", roles["parent"],
		"-stop-file", stopFile,
	)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	exited := make(chan struct{})
	var exitErr error
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(logFile, line)
			if line == "status=ready" {
				select {
				case <-ready:
				default:
					close(ready)
				}
			}
		}
		_ = logFile.Close()
		exitErr = command.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(stopFile, []byte("stop"), 0o600)
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			_ = command.Process.Kill()
			<-exited
		}
	})
	select {
	case <-ready:
	case <-exited:
		t.Fatalf("tunneldemo exited before ready: %v; see %s", exitErr, logPath)
	case <-time.After(45 * time.Second):
		t.Fatalf("tunneldemo readiness timeout; see %s", logPath)
	}

	processes := map[string]*flowProcess{
		"excluded":   startFlowProcess(t, roles["excluded"], "client", ""),
		"descendant": startFlowProcess(t, roles["parent"], "descendant", roles["descendant"]),
		"included":   startFlowProcess(t, roles["included"], "client", ""),
	}
	manifest, err := os.OpenFile(filepath.Join(artifactDirectory, "packet-flow-observations.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(manifest)
	defer func() { _ = manifest.Close() }()
	sequence := 0
	for _, role := range []string{"included", "excluded", "descendant"} {
		expectedPath := "underlay"
		wantIPv4 := "198.18.1.2"
		wantIPv6 := "fd00:18:1::2"
		if role == "included" {
			expectedPath = "tunnel"
			wantIPv4 = "10.77.0.2"
			wantIPv6 = "fd00:77::2"
		}
		for _, flow := range []struct {
			network  string
			address  string
			wantHost string
		}{
			{network: "tcp4", address: flowServiceIPv4, wantHost: wantIPv4},
			{network: "udp4", address: flowServiceIPv4, wantHost: wantIPv4},
			{network: "tcp6", address: flowServiceIPv6, wantHost: wantIPv6},
			{network: "udp6", address: flowServiceIPv6, wantHost: wantIPv6},
		} {
			sequence++
			token := fmt.Sprintf("TUNNELDEMO_%02d", sequence)
			response := processes[role].request(t, flowRequest{
				Operation: "once", Network: flow.network, Address: flow.address, Token: token,
			})
			if response.Error != "" {
				t.Fatalf("%s %s: %s", role, flow.network, response.Error)
			}
			if host := flowHost(response.LocalAddr); !strings.EqualFold(host, flow.wantHost) {
				t.Fatalf("%s %s local address = %s; want %s", role, flow.network, host, flow.wantHost)
			}
			if err := encoder.Encode(flowObservation{
				Token: token, Cycle: 1, Phase: "tunneldemo", Profile: "dual-stack",
				Role: role, Network: flow.network, Flow: "new", ExpectedPath: expectedPath,
				Outcome: "echo", LocalAddr: response.LocalAddr,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, network := range []string{"udp4", "udp6"} {
		sequence++
		token := fmt.Sprintf("TDEMO_LARGE_%02d_", sequence) + strings.Repeat("X", 1100)
		address := flowServiceIPv4
		wantHost := "10.77.0.2"
		if network == "udp6" {
			address = flowServiceIPv6
			wantHost = "fd00:77::2"
		}
		response := processes["included"].request(t, flowRequest{
			Operation: "once", Network: network, Address: address, Token: token,
		})
		if response.Error != "" {
			t.Fatalf("large included %s: %s", network, response.Error)
		}
		if host := flowHost(response.LocalAddr); !strings.EqualFold(host, wantHost) {
			t.Fatalf("large included %s local address = %s; want %s", network, host, wantHost)
		}
		if err := encoder.Encode(flowObservation{
			Token: token, Cycle: 1, Phase: "tunneldemo-large", Profile: "dual-stack",
			Role: "included", Network: network, Flow: "new", ExpectedPath: "tunnel",
			Outcome: "echo", LocalAddr: response.LocalAddr,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := manifest.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stopFile, []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
		if exitErr != nil {
			t.Fatalf("tunneldemo cleanup: %v; see %s", exitErr, logPath)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("tunneldemo cleanup timeout; see %s", logPath)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(logData, []byte("event id=0")) {
		t.Fatalf("tunneldemo did not consume a process event; see %s", logPath)
	}
	assertTunnelDemoCleanup(t)
	assertExistingOwnerRejected(t, demoExecutable, roles["excluded"])
	assertTunnelDemoRestarts(t, demoExecutable, roles["excluded"], artifactDirectory)
	assertTunnelDemoCleanup(t)
}

func assertTunnelDemoRestarts(t *testing.T, demoExecutable, exclusion, artifactDirectory string) {
	t.Helper()
	stopFile := filepath.Join(t.TempDir(), "restart-stop")
	command := exec.Command(demoExecutable,
		"-peer", "198.18.0.1:51900",
		"-internet-ipv4", "198.18.1.2",
		"-internet-ipv6", "fd00:18:1::2",
		"-exclude", exclusion,
		"-stop-file", stopFile,
	)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	finished := false
	t.Cleanup(func() {
		if finished {
			return
		}
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	var log bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(&log, line)
			if line == "status=ready" {
				select {
				case <-ready:
				default:
					close(ready)
				}
			}
		}
		done <- errors.Join(scanner.Err(), command.Wait())
	}()
	select {
	case <-ready:
	case err := <-done:
		finished = true
		t.Fatalf("restarted tunneldemo exited before ready: %v\n%s", err, log.String())
	case <-time.After(45 * time.Second):
		_ = command.Process.Kill()
		<-done
		finished = true
		t.Fatalf("restarted tunneldemo readiness timeout\n%s", log.String())
	}
	if err := os.WriteFile(stopFile, []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatalf("restarted tunneldemo cleanup: %v\n%s", err, log.String())
		}
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		<-done
		finished = true
		t.Fatalf("restarted tunneldemo cleanup timeout\n%s", log.String())
	}
	if err := os.WriteFile(filepath.Join(artifactDirectory, "tunneldemo-restart.log"), log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertTunnelDemoCleanup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	controller, err := openControllerAfterCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	state, err := controller.State(ctx)
	if err != nil || state != splittunnel.StateStarted {
		t.Fatalf("driver state after tunneldemo = %s, %v; want started", state, err)
	}
	check := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command",
		"if (Get-NetAdapter -Name 'Mullvad split tunnel demo' -ErrorAction SilentlyContinue) { exit 1 }")
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("TUN adapter remains after cleanup: %v: %s", err, output)
	}
}

func assertExistingOwnerRejected(t *testing.T, demoExecutable, exclusion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := splittunnel.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	command := exec.CommandContext(ctx, demoExecutable,
		"-peer", "198.18.0.1:51900",
		"-internet-ipv4", "198.18.1.2",
		"-exclude", exclusion,
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "another owner may be active") {
		t.Fatalf("existing owner result = %v: %s", err, output)
	}
	state, err := owner.State(ctx)
	if err != nil || state != splittunnel.StateStarted {
		t.Fatalf("owner state after rejection = %s, %v; want started", state, err)
	}
	check := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command",
		"if (Get-NetAdapter -Name 'Mullvad split tunnel demo' -ErrorAction SilentlyContinue) { exit 1 }")
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("rejected command created a TUN adapter: %v: %s", err, output)
	}
}

func openControllerAfterCleanup(ctx context.Context) (*splittunnel.Controller, error) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		controller, err := splittunnel.Open()
		if err == nil {
			return controller, nil
		}
		select {
		case <-deadline.Done():
			return nil, fmt.Errorf("open controller after tunneldemo: %w", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
