package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TestMode represents a forwarding mode to test
type TestMode struct {
	Name          string
	Type          string // "remote", "cloud-self", "agent-cloud", "p2p"
	Protocol      string // "tcp"
	ListenPort    int
	SourceAgentID string
	TargetAgentID string
	TargetHost    string
	TargetPort    int
	RateLimit     int64 // bytes per second, 0 = unlimited
}

// TestRunner manages the test environment
type TestRunner struct {
	cloudAddr      string
	cloudToken     string
	cloudProcess   *exec.Cmd
	agentProcesses []*exec.Cmd
	testServers    []*TestServer
	modes          []TestMode
	mu             sync.Mutex
	workDir        string
	httpClient     *http.Client
	useExternal    bool   // Use external cloud server
	externalServer string // External server URL (e.g., "localhost:1880")
}

// NewTestRunner creates a new test runner
func NewTestRunner(workDir string) *TestRunner {
	return &TestRunner{
		cloudAddr:  ":11880", // Use different port from dev server (:1880)
		cloudToken: "integration-test-token",
		workDir:    workDir,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewTestRunnerWithExternal creates a test runner using an external cloud server
func NewTestRunnerWithExternal(workDir, serverAddr, token string) *TestRunner {
	// Normalize server address
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":1880"
	}
	addr := serverAddr
	if !strings.HasPrefix(addr, ":") {
		// Extract port from address like "localhost:1880"
		parts := strings.Split(addr, ":")
		if len(parts) == 2 {
			addr = ":" + parts[1]
		}
	}

	return &TestRunner{
		cloudAddr:      addr,
		cloudToken:     token,
		workDir:        workDir,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		useExternal:    true,
		externalServer: serverAddr,
	}
}

// SetupEnvironment sets up the complete test environment
func (r *TestRunner) SetupEnvironment() error {
	log.Println("[Runner] Setting up test environment...")

	// Start test servers
	if err := r.startTestServers(); err != nil {
		return fmt.Errorf("failed to start test servers: %v", err)
	}

	if r.useExternal {
		// Using external cloud server
		log.Printf("[Runner] Using external cloud server: %s", r.externalServer)

		// Wait for external cloud to be ready
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("external cloud not ready: %v", err)
		}
	} else {
		// Start our own cloud server
		if err := r.startCloud(); err != nil {
			return fmt.Errorf("failed to start cloud: %v", err)
		}

		// Wait for cloud to be ready
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("cloud not ready: %v", err)
		}
	}

	// Start agents
	if err := r.startAgents(); err != nil {
		return fmt.Errorf("failed to start agents: %v", err)
	}

	// Wait for agents to connect
	if err := r.waitForAgents(2); err != nil {
		return fmt.Errorf("agents not ready: %v", err)
	}

	// Configure forwarding rules
	if err := r.configureForwardRules(); err != nil {
		return fmt.Errorf("failed to configure rules: %v", err)
	}

	// Wait for rules to be active
	time.Sleep(2 * time.Second)

	log.Println("[Runner] Test environment ready")
	return nil
}

// SetupForSingleMode sets up environment for testing a single mode
func (r *TestRunner) SetupForSingleMode(modeName string) error {
	log.Printf("[Runner] Setting up for single mode: %s", modeName)

	// Start test servers
	if err := r.startTestServers(); err != nil {
		return fmt.Errorf("failed to start test servers: %v", err)
	}

	if r.useExternal {
		log.Printf("[Runner] Using external cloud server: %s", r.externalServer)
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("external cloud not ready: %v", err)
		}
	} else {
		if err := r.startCloud(); err != nil {
			return fmt.Errorf("failed to start cloud: %v", err)
		}
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("cloud not ready: %v", err)
		}
	}

	// Start agents
	if err := r.startAgents(); err != nil {
		return fmt.Errorf("failed to start agents: %v", err)
	}

	if err := r.waitForAgents(2); err != nil {
		return fmt.Errorf("agents not ready: %v", err)
	}

	// Configure only the specified mode
	r.initModes()
	for _, mode := range r.modes {
		if mode.Name == modeName || mode.Type == modeName {
			if err := r.createForwardRule(mode); err != nil {
				return fmt.Errorf("failed to create rule %s: %v", mode.Name, err)
			}
			log.Printf("[Runner] Created rule: %s (%s)", mode.Name, mode.Type)
			r.modes = []TestMode{mode} // Keep only this mode
			break
		}
	}

	time.Sleep(2 * time.Second)
	log.Println("[Runner] Single mode environment ready")
	return nil
}

// initModes initializes the test modes without creating rules
func (r *TestRunner) initModes() {
	r.modes = []TestMode{
		{
			Name:          "Mode1-Remote",
			Type:          "remote",
			Protocol:      "tcp",
			ListenPort:    12001,
			TargetAgentID: "agent-1",
			TargetHost:    "127.0.0.1",
			TargetPort:    19001,
		},
		{
			Name:       "Mode2-CloudSelf",
			Type:       "cloud-self",
			Protocol:   "tcp",
			ListenPort: 12002,
			TargetHost: "127.0.0.1",
			TargetPort: 19001,
		},
		{
			Name:          "Mode3-AgentCloud",
			Type:          "agent-cloud",
			Protocol:      "tcp",
			ListenPort:    12003,
			SourceAgentID: "agent-1",
			TargetHost:    "127.0.0.1",
			TargetPort:    19002,
		},
		{
			Name:          "Mode4-P2P",
			Type:          "p2p",
			Protocol:      "tcp",
			ListenPort:    12004,
			SourceAgentID: "agent-1",
			TargetAgentID: "agent-2",
			TargetHost:    "127.0.0.1",
			TargetPort:    19002,
		},
	}
}

// startTestServers starts the echo test servers
func (r *TestRunner) startTestServers() error {
	ports := []int{19001, 19002} // Use high ports to avoid conflicts
	for _, port := range ports {
		server := NewTestServer(port)
		if err := server.Start(); err != nil {
			return err
		}
		r.testServers = append(r.testServers, server)
	}
	return nil
}

// startCloud starts the cloud server
func (r *TestRunner) startCloud() error {
	// Prepare dist directory for embedded frontend
	distDir := r.workDir + "/cmd/cloud/dist"
	os.MkdirAll(distDir, 0755)
	os.WriteFile(distDir+"/index.html", []byte("<html><body>Test</body></html>"), 0644)

	cmd := exec.Command("go", "run", "./cmd/cloud",
		"-addr", r.cloudAddr,
		"-token", r.cloudToken,
		"-db", "/tmp/natsvr-test.db",
	)
	cmd.Dir = r.workDir
	cmd.Stdout = &prefixWriter{prefix: "[cloud] ", writer: os.Stdout}
	cmd.Stderr = &prefixWriter{prefix: "[cloud] ", writer: os.Stderr}

	if err := cmd.Start(); err != nil {
		return err
	}

	r.mu.Lock()
	r.cloudProcess = cmd
	r.mu.Unlock()

	log.Printf("[Runner] Cloud started with PID %d", cmd.Process.Pid)
	return nil
}

// startAgents starts the agent processes
func (r *TestRunner) startAgents() error {
	agents := []struct {
		name string
	}{
		{name: "agent-1"},
		{name: "agent-2"},
	}

	for _, a := range agents {
		var wsURL string
		if r.useExternal {
			// Use external server URL
			wsURL = fmt.Sprintf("ws://%s/ws", r.externalServer)
		} else {
			wsURL = fmt.Sprintf("ws://localhost%s/ws", r.cloudAddr)
		}

		cmd := exec.Command("go", "run", "./cmd/agent",
			"-server", wsURL,
			"-token", r.cloudToken,
			"-name", a.name,
		)
		cmd.Dir = r.workDir
		cmd.Stdout = &prefixWriter{prefix: fmt.Sprintf("[%s] ", a.name), writer: os.Stdout}
		cmd.Stderr = &prefixWriter{prefix: fmt.Sprintf("[%s] ", a.name), writer: os.Stderr}

		if err := cmd.Start(); err != nil {
			return err
		}

		r.mu.Lock()
		r.agentProcesses = append(r.agentProcesses, cmd)
		r.mu.Unlock()

		log.Printf("[Runner] Agent %s started with PID %d, connecting to %s", a.name, cmd.Process.Pid, wsURL)
	}

	return nil
}

// waitForCloud waits for cloud server to be ready
func (r *TestRunner) waitForCloud() error {
	log.Println("[Runner] Waiting for cloud server...")
	deadline := time.Now().Add(30 * time.Second)

	apiBase := r.getAPIBase()

	for time.Now().Before(deadline) {
		resp, err := r.httpClient.Get(fmt.Sprintf("%s/api/version", apiBase))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				log.Println("[Runner] Cloud server is ready")
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for cloud server")
}

// getAPIBase returns the HTTP API base URL
func (r *TestRunner) getAPIBase() string {
	if r.useExternal {
		return fmt.Sprintf("http://%s", r.externalServer)
	}
	return fmt.Sprintf("http://localhost%s", r.cloudAddr)
}

// waitForAgents waits for specified number of agents to connect
func (r *TestRunner) waitForAgents(count int) error {
	log.Printf("[Runner] Waiting for %d agents to connect...", count)
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		agents, err := r.getAgents()
		if err == nil && len(agents) >= count {
			log.Printf("[Runner] %d agents connected", len(agents))
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for agents")
}

// getAgents fetches connected agents from API
func (r *TestRunner) getAgents() ([]map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/agents", r.getAPIBase()), nil)
	req.Header.Set("Authorization", "Bearer "+r.cloudToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var agents []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return nil, err
	}

	return agents, nil
}

// configureForwardRules configures the 4 forwarding modes
func (r *TestRunner) configureForwardRules() error {
	log.Println("[Runner] Configuring forwarding rules...")

	r.initModes()

	for _, mode := range r.modes {
		if err := r.createForwardRule(mode); err != nil {
			return fmt.Errorf("failed to create rule %s: %v", mode.Name, err)
		}
		log.Printf("[Runner] Created rule: %s (%s)", mode.Name, mode.Type)
	}

	return nil
}

// createForwardRule creates a forwarding rule via API
func (r *TestRunner) createForwardRule(mode TestMode) error {
	payload := map[string]interface{}{
		"name":       mode.Name,
		"type":       mode.Type,
		"protocol":   mode.Protocol,
		"listenPort": mode.ListenPort,
		"targetHost": mode.TargetHost,
		"targetPort": mode.TargetPort,
	}

	if mode.SourceAgentID != "" {
		payload["sourceAgentId"] = mode.SourceAgentID
	}
	if mode.TargetAgentID != "" {
		payload["targetAgentId"] = mode.TargetAgentID
	}
	if mode.RateLimit > 0 {
		payload["rateLimit"] = mode.RateLimit
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/api/forward-rules", r.getAPIBase()),
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+r.cloudToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// RunSingleModeTest runs tests for a single mode and returns the report
func (r *TestRunner) RunSingleModeTest(modeName string) (*ModeTestReport, error) {
	if len(r.modes) == 0 {
		return nil, fmt.Errorf("no modes configured")
	}

	var mode TestMode
	for _, m := range r.modes {
		if m.Name == modeName || m.Type == modeName {
			mode = m
			break
		}
	}

	if mode.Name == "" {
		return nil, fmt.Errorf("mode not found: %s", modeName)
	}

	log.Printf("\n[Runner] ========== Testing Mode: %s ==========", mode.Name)

	modeReport := &ModeTestReport{
		ModeName: mode.Name,
		ModeType: mode.Type,
	}

	addr := r.GetConnectAddress(mode)
	log.Printf("[Runner] Connect address: %s", addr)

	time.Sleep(time.Second)

	// Run connectivity test
	log.Printf("[Runner] Running connectivity test...")
	if err := r.testConnectivity(addr); err != nil {
		log.Printf("[Runner] Connectivity test failed: %v", err)
		modeReport.Error = err.Error()
		return modeReport, nil
	}

	// Run all tests
	log.Printf("[Runner] Running consistency test...")
	modeReport.Consistency = r.runConsistencyTest(addr)

	log.Printf("[Runner] Running latency test...")
	modeReport.Latency = r.runLatencyTest(addr)

	log.Printf("[Runner] Running throughput test...")
	modeReport.Throughput = r.runThroughputTest(addr)

	log.Printf("[Runner] Running stress test...")
	modeReport.Stress = r.runStressTest(addr)

	return modeReport, nil
}

// GetAvailableModes returns the list of available test modes
func (r *TestRunner) GetAvailableModes() []string {
	r.initModes()
	modes := make([]string, len(r.modes))
	for i, m := range r.modes {
		modes[i] = m.Name
	}
	return modes
}

// SetupForRateLimitTest sets up environment for rate limit testing
func (r *TestRunner) SetupForRateLimitTest(rateLimitBps int64) error {
	log.Printf("[Runner] Setting up for rate limit test: %d bytes/sec", rateLimitBps)

	// Start test servers
	if err := r.startTestServers(); err != nil {
		return fmt.Errorf("failed to start test servers: %v", err)
	}

	if r.useExternal {
		log.Printf("[Runner] Using external cloud server: %s", r.externalServer)
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("external cloud not ready: %v", err)
		}
	} else {
		if err := r.startCloud(); err != nil {
			return fmt.Errorf("failed to start cloud: %v", err)
		}
		if err := r.waitForCloud(); err != nil {
			return fmt.Errorf("cloud not ready: %v", err)
		}
	}

	// Start agents
	if err := r.startAgents(); err != nil {
		return fmt.Errorf("failed to start agents: %v", err)
	}

	if err := r.waitForAgents(2); err != nil {
		return fmt.Errorf("agents not ready: %v", err)
	}

	time.Sleep(1 * time.Second)
	log.Println("[Runner] Rate limit test environment ready")
	return nil
}

// createRateLimitRule creates a forwarding rule with optional rate limit
func (r *TestRunner) createRateLimitRule(name string, rateLimit int64, port int) error {
	mode := TestMode{
		Name:       name,
		Type:       "cloud-self",
		Protocol:   "tcp",
		ListenPort: port,
		TargetHost: "127.0.0.1",
		TargetPort: 19001,
		RateLimit:  rateLimit,
	}

	if err := r.createForwardRule(mode); err != nil {
		return fmt.Errorf("failed to create rule %s: %v", name, err)
	}

	if rateLimit > 0 {
		log.Printf("[Runner] Created rule: %s (limit: %d bytes/s = %.2f MB/s)", name, rateLimit, float64(rateLimit)/1024/1024)
	} else {
		log.Printf("[Runner] Created rule: %s (no limit)", name)
	}

	r.modes = append(r.modes, mode)
	return nil
}

// deleteRule deletes a forwarding rule by name
func (r *TestRunner) deleteRule(name string) error {
	req, _ := http.NewRequest("DELETE",
		fmt.Sprintf("%s/api/forward-rules/%s", r.getAPIBase(), name),
		nil)
	req.Header.Set("Authorization", "Bearer "+r.cloudToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Remove from modes
	for i, m := range r.modes {
		if m.Name == name {
			r.modes = append(r.modes[:i], r.modes[i+1:]...)
			break
		}
	}

	return nil
}

// RunRateLimitTest runs the rate limit test with baseline comparison
func (r *TestRunner) RunRateLimitTest(rateLimitBps int64, testDuration time.Duration) (*RateLimitTestReport, error) {
	report := &RateLimitTestReport{
		ExpectedRateBps:  rateLimitBps,
		ExpectedRateMBps: float64(rateLimitBps) / 1024 / 1024,
		TolerancePercent: 30,
	}

	// Step 1: Measure baseline throughput without rate limiting
	log.Println("[Runner] Step 1: Measuring baseline throughput (no rate limit)...")

	if err := r.createRateLimitRule("Baseline-Test", 0, 12009); err != nil {
		return nil, fmt.Errorf("failed to create baseline rule: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	baselineRate, baselineBytes, err := r.measureThroughput("127.0.0.1:12009", testDuration/2)
	if err != nil {
		return nil, fmt.Errorf("baseline test failed: %v", err)
	}

	report.BaselineRateBps = int64(baselineRate)
	report.BaselineRateMBps = baselineRate / 1024 / 1024
	log.Printf("[Runner] Baseline: %.2f MB/s (%d bytes in %v)",
		report.BaselineRateMBps, baselineBytes, testDuration/2)

	// Delete baseline rule
	r.deleteRule("Baseline-Test")
	time.Sleep(500 * time.Millisecond)

	// Step 2: Measure throughput with rate limiting
	log.Printf("[Runner] Step 2: Measuring throughput with rate limit (%.2f MB/s)...",
		float64(rateLimitBps)/1024/1024)

	if err := r.createRateLimitRule("RateLimit-Test", rateLimitBps, 12010); err != nil {
		return nil, fmt.Errorf("failed to create rate limited rule: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	limitedRate, limitedBytes, err := r.measureThroughput("127.0.0.1:12010", testDuration)
	if err != nil {
		return nil, fmt.Errorf("rate limited test failed: %v", err)
	}

	report.ActualRateBps = int64(limitedRate)
	report.ActualRateMBps = limitedRate / 1024 / 1024
	report.BytesTransferred = limitedBytes
	report.Duration = testDuration

	// Calculate accuracy (actual vs expected)
	report.RateAccuracy = limitedRate / float64(rateLimitBps) * 100

	// Calculate speed reduction from baseline
	if baselineRate > 0 {
		report.SpeedReduction = (1 - limitedRate/baselineRate) * 100
	}

	// Rate limiting is effective if:
	// 1. Actual rate is at or below expected rate (plus some tolerance for burst)
	// 2. There is actual speed reduction from baseline (if baseline > limit)
	report.RateLimitEffective = limitedRate <= float64(rateLimitBps)*1.2 // Allow 20% burst

	// Within tolerance:
	// - Rate should not exceed 120% of expected (allowing some burst)
	// - Rate should be at least 50% of expected (reasonable efficiency)
	// Note: In bidirectional copy, rate is shared between both directions,
	// so each direction gets roughly half of the total limit
	lowerBound := float64(rateLimitBps) * 0.5
	upperBound := float64(rateLimitBps) * 1.2
	report.WithinTolerance = limitedRate >= lowerBound && limitedRate <= upperBound

	// If baseline is lower than limit, adjust expectations
	if baselineRate < float64(rateLimitBps) {
		log.Printf("[Runner] Note: Baseline (%.2f MB/s) is lower than rate limit (%.2f MB/s)",
			baselineRate/1024/1024, float64(rateLimitBps)/1024/1024)
		// In this case, rate limiting can't be fully verified, but should still not exceed limit
		report.WithinTolerance = limitedRate <= float64(rateLimitBps)*1.2
		report.RateLimitEffective = true // Can't verify reduction, but not exceeding limit
	}

	return report, nil
}

// measureThroughput measures actual throughput to an address
func (r *TestRunner) measureThroughput(addr string, duration time.Duration) (float64, int64, error) {
	client := NewTestClient(addr)
	if err := client.Connect(); err != nil {
		return 0, 0, fmt.Errorf("connect failed: %v", err)
	}
	defer client.Close()

	// Verify connectivity
	pingResult := client.Ping()
	if !pingResult.Success {
		return 0, 0, fmt.Errorf("ping failed: %v", pingResult.Error)
	}

	// Get initial server stats
	var initialBytes int64
	if len(r.testServers) > 0 {
		initialStats := r.testServers[0].GetStats()
		initialBytes = initialStats.BytesReceived
	}

	// Run throughput test
	_, err := client.RunRateLimitTest(0, duration, 0) // 0 = no expected limit
	if err != nil {
		return 0, 0, err
	}

	// Get final server stats
	var finalBytes int64
	if len(r.testServers) > 0 {
		finalStats := r.testServers[0].GetStats()
		finalBytes = finalStats.BytesReceived
	}

	bytesTransferred := finalBytes - initialBytes
	rate := float64(bytesTransferred) / duration.Seconds()

	return rate, bytesTransferred, nil
}

// RateLimitTestReport holds rate limit test results
type RateLimitTestReport struct {
	// Baseline (no rate limit)
	BaselineRateBps  int64   `json:"baselineRateBps"`
	BaselineRateMBps float64 `json:"baselineRateMBps"`
	// Expected rate limit
	ExpectedRateBps  int64   `json:"expectedRateBps"`
	ExpectedRateMBps float64 `json:"expectedRateMBps"`
	// Actual measured rate
	ActualRateBps  int64   `json:"actualRateBps"`
	ActualRateMBps float64 `json:"actualRateMBps"`
	// Test details
	Duration         time.Duration `json:"duration"`
	BytesTransferred int64         `json:"bytesTransferred"`
	RateAccuracy     float64       `json:"rateAccuracy"` // percentage of expected
	WithinTolerance  bool          `json:"withinTolerance"`
	TolerancePercent float64       `json:"tolerancePercent"`
	// Rate limiting effectiveness
	RateLimitEffective bool    `json:"rateLimitEffective"` // true if rate was actually limited
	SpeedReduction     float64 `json:"speedReduction"`     // percentage reduction from baseline
}

// GetModes returns the configured test modes
func (r *TestRunner) GetModes() []TestMode {
	return r.modes
}

// GetConnectAddress returns the address to connect to for a mode
func (r *TestRunner) GetConnectAddress(mode TestMode) string {
	switch mode.Type {
	case "remote", "cloud-self":
		// Connect directly to cloud listening port
		return fmt.Sprintf("127.0.0.1:%d", mode.ListenPort)
	case "agent-cloud", "p2p":
		// Connect to agent's listening port (localhost since we run locally)
		return fmt.Sprintf("127.0.0.1:%d", mode.ListenPort)
	}
	return ""
}

// Cleanup stops all processes and servers
func (r *TestRunner) Cleanup() {
	log.Println("[Runner] Cleaning up test environment...")

	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop agents
	for _, cmd := range r.agentProcesses {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
	r.agentProcesses = nil

	// Stop cloud
	if r.cloudProcess != nil && r.cloudProcess.Process != nil {
		r.cloudProcess.Process.Kill()
		r.cloudProcess = nil
	}

	// Stop test servers
	for _, s := range r.testServers {
		s.Stop()
	}
	r.testServers = nil

	// Remove test database
	os.Remove("/tmp/natsvr-test.db")

	log.Println("[Runner] Cleanup complete")
}

// RunAllTests runs all test suites
func (r *TestRunner) RunAllTests() (*FullTestReport, error) {
	report := &FullTestReport{
		StartTime: time.Now(),
		Modes:     make(map[string]*ModeTestReport),
	}

	for _, mode := range r.modes {
		log.Printf("\n[Runner] ========== Testing Mode: %s ==========", mode.Name)

		modeReport := &ModeTestReport{
			ModeName: mode.Name,
			ModeType: mode.Type,
		}

		addr := r.GetConnectAddress(mode)
		log.Printf("[Runner] Connect address: %s", addr)

		// Wait a bit for the mode's listener to be ready
		time.Sleep(time.Second)

		// Run connectivity test first
		log.Printf("[Runner] Running connectivity test...")
		if err := r.testConnectivity(addr); err != nil {
			log.Printf("[Runner] Connectivity test failed: %v", err)
			modeReport.Error = err.Error()
			report.Modes[mode.Name] = modeReport
			continue
		}

		// Run consistency test
		log.Printf("[Runner] Running consistency test...")
		consistencyResult := r.runConsistencyTest(addr)
		modeReport.Consistency = consistencyResult

		// Run latency test
		log.Printf("[Runner] Running latency test...")
		latencyResult := r.runLatencyTest(addr)
		modeReport.Latency = latencyResult

		// Run throughput test
		log.Printf("[Runner] Running throughput test...")
		throughputResult := r.runThroughputTest(addr)
		modeReport.Throughput = throughputResult

		// Run stress test
		log.Printf("[Runner] Running stress test...")
		stressResult := r.runStressTest(addr)
		modeReport.Stress = stressResult

		report.Modes[mode.Name] = modeReport
	}

	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)

	return report, nil
}

func (r *TestRunner) testConnectivity(addr string) error {
	client := NewTestClient(addr)
	if err := client.Connect(); err != nil {
		return err
	}
	defer client.Close()

	result := client.Ping()
	if !result.Success {
		return fmt.Errorf("ping failed: %v", result.Error)
	}

	log.Printf("[Runner] Connectivity OK, RTT: %v", result.Latency)
	return nil
}

func (r *TestRunner) runConsistencyTest(addr string) *ConsistencyTestResult {
	client := NewTestClient(addr)
	if err := client.Connect(); err != nil {
		return &ConsistencyTestResult{Errors: []error{err}}
	}
	defer client.Close()

	// Test different data sizes
	sizes := []int{1, 1024, 32 * 1024} // 1B, 1KB, 32KB
	aggregated := &ConsistencyTestResult{}

	for _, size := range sizes {
		result, err := client.RunConsistencyTest(100, size)
		if err != nil {
			aggregated.Errors = append(aggregated.Errors, err)
			continue
		}

		aggregated.TotalMessages += result.TotalMessages
		aggregated.SuccessMessages += result.SuccessMessages
		aggregated.ChecksumErrors += result.ChecksumErrors
		aggregated.DataMismatch += result.DataMismatch
		aggregated.SequenceMismatch += result.SequenceMismatch
		aggregated.Errors = append(aggregated.Errors, result.Errors...)

		log.Printf("[Runner]   Size %d: %d/%d success", size, result.SuccessMessages, result.TotalMessages)
	}

	return aggregated
}

func (r *TestRunner) runLatencyTest(addr string) *LatencyTestResult {
	client := NewTestClient(addr)
	if err := client.Connect(); err != nil {
		return &LatencyTestResult{}
	}
	defer client.Close()

	result, _ := client.RunLatencyTest(200, 64) // 200 samples, 64 byte payload
	return result
}

func (r *TestRunner) runThroughputTest(addr string) *ThroughputTestResult {
	client := NewTestClient(addr)
	if err := client.Connect(); err != nil {
		return &ThroughputTestResult{}
	}
	defer client.Close()

	result, _ := client.RunThroughputTest(5*time.Second, 32*1024) // 5 seconds, 32KB chunks
	return result
}

func (r *TestRunner) runStressTest(addr string) *StressTestResult {
	result, _ := RunStressTest(addr, 50, 5*time.Second, 1024) // 50 concurrent, 5 seconds, 1KB
	return result
}

// GetServerStats returns test server statistics
func (r *TestRunner) GetServerStats() []ServerStats {
	var stats []ServerStats
	for _, s := range r.testServers {
		stats = append(stats, s.GetStats())
	}
	return stats
}

// prefixWriter adds a prefix to each line of output
type prefixWriter struct {
	prefix string
	writer io.Writer
	buf    []byte
}

func (w *prefixWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)

	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}

		line := w.buf[:idx+1]
		w.buf = w.buf[idx+1:]

		if len(strings.TrimSpace(string(line))) > 0 {
			w.writer.Write([]byte(w.prefix))
			w.writer.Write(line)
		}
	}

	return len(p), nil
}
