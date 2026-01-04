package integration

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Config holds the test configuration
type Config struct {
	WorkDir       string
	SaveJSON      bool
	SaveMarkdown  bool
	OutputDir     string
	Verbose       bool
	SkipCleanup   bool
	
	// External server options
	Server        string // External cloud server address (e.g., "localhost:1880")
	Token         string // Authentication token
	
	// Single mode testing
	Mode          string // Specific mode to test (e.g., "remote", "cloud-self", "agent-cloud", "p2p")
	ListModes     bool   // List available modes
	
	// Rate limit testing
	RateLimitTest bool  // Run rate limit test
	RateLimitMBps float64 // Rate limit in MB/s for testing
}

// Main is the main entry point for integration tests
func Main() {
	cfg := &Config{}

	flag.StringVar(&cfg.WorkDir, "workdir", "", "Working directory (project root)")
	flag.BoolVar(&cfg.SaveJSON, "json", false, "Save JSON report")
	flag.BoolVar(&cfg.SaveMarkdown, "markdown", false, "Save Markdown report")
	flag.StringVar(&cfg.OutputDir, "output", ".", "Output directory for reports")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&cfg.SkipCleanup, "skip-cleanup", false, "Skip cleanup after tests")
	
	// External server options
	flag.StringVar(&cfg.Server, "server", "", "External cloud server address (e.g., localhost:1880)")
	flag.StringVar(&cfg.Token, "token", "", "Authentication token for external server")
	
	// Single mode testing
	flag.StringVar(&cfg.Mode, "mode", "", "Test specific mode (remote, cloud-self, agent-cloud, p2p)")
	flag.BoolVar(&cfg.ListModes, "list", false, "List available test modes")
	
	// Rate limit testing
	flag.BoolVar(&cfg.RateLimitTest, "ratelimit", false, "Run rate limit test")
	flag.Float64Var(&cfg.RateLimitMBps, "ratelimit-mbps", 1.0, "Rate limit to test in MB/s (default: 1.0)")
	
	flag.Parse()

	// Auto-detect workdir if not specified
	if cfg.WorkDir == "" {
		cwd, _ := os.Getwd()
		cfg.WorkDir = findProjectRoot(cwd)
		if cfg.WorkDir == "" {
			log.Fatal("Could not find project root. Please specify -workdir")
		}
	}

	// List modes and exit
	if cfg.ListModes {
		listAvailableModes()
		return
	}

	log.Printf("Project root: %s", cfg.WorkDir)

	// Run the tests
	var exitCode int
	if cfg.RateLimitTest {
		exitCode = RunRateLimitTests(cfg)
	} else if cfg.Mode != "" {
		exitCode = RunSingleModeTests(cfg)
	} else {
		exitCode = RunIntegrationTests(cfg)
	}
	os.Exit(exitCode)
}

// listAvailableModes prints available test modes
func listAvailableModes() {
	fmt.Println("Available test modes:")
	fmt.Println()
	fmt.Println("  Mode1-Remote     (remote)       Cloud listens, forwards to Agent -> TestServer")
	fmt.Println("  Mode2-CloudSelf  (cloud-self)   Cloud listens, forwards directly to TestServer")
	fmt.Println("  Mode3-AgentCloud (agent-cloud)  Agent listens, forwards via Cloud to TestServer")
	fmt.Println("  Mode4-P2P        (p2p)          Agent1 listens, forwards via Cloud to Agent2 -> TestServer")
	fmt.Println()
	fmt.Println("Usage examples:")
	fmt.Println("  ./test.sh full                           # Run all modes")
	fmt.Println("  ./test.sh mode remote                    # Test remote mode only")
	fmt.Println("  ./test.sh mode p2p -server localhost:1880 -token dev-token")
	fmt.Println("  ./test.sh ratelimit                      # Test rate limiting (1 MB/s)")
	fmt.Println("  ./test.sh ratelimit -ratelimit-mbps 5.0  # Test rate limiting (5 MB/s)")
	fmt.Println()
}

// RunRateLimitTests runs rate limit tests
func RunRateLimitTests(cfg *Config) int {
	rateLimitBps := int64(cfg.RateLimitMBps * 1024 * 1024) // Convert MB/s to bytes/s
	
	log.Println("========================================")
	log.Printf("  NatSvr Rate Limit Test: %.2f MB/s", cfg.RateLimitMBps)
	log.Println("========================================")

	var runner *TestRunner
	if cfg.Server != "" && cfg.Token != "" {
		runner = NewTestRunnerWithExternal(cfg.WorkDir, cfg.Server, cfg.Token)
		log.Printf("Using external server: %s", cfg.Server)
	} else {
		runner = NewTestRunner(cfg.WorkDir)
		log.Println("Using internal test server")
	}

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, cleaning up...")
		runner.Cleanup()
		os.Exit(1)
	}()

	if !cfg.SkipCleanup {
		defer runner.Cleanup()
	}

	// Setup for rate limit test
	if err := runner.SetupForRateLimitTest(rateLimitBps); err != nil {
		log.Printf("Failed to setup environment: %v", err)
		return 1
	}

	// Run rate limit test for 10 seconds
	testDuration := 10 * time.Second
	report, err := runner.RunRateLimitTest(rateLimitBps, testDuration)
	if err != nil {
		log.Printf("Rate limit test failed: %v", err)
		return 1
	}

	// Print report
	printRateLimitReport(report)

	// Print server stats
	printServerStats(runner)

	// Determine result - main criteria: rate limit is effective (not exceeded)
	if report.RateLimitEffective {
		log.Println("\n✓ Rate limit test PASSED!")
		log.Printf("  Baseline: %.2f MB/s → Limited: %.2f MB/s (%.1f%% of %.2f MB/s limit)", 
			report.BaselineRateMBps, report.ActualRateMBps, report.RateAccuracy, report.ExpectedRateMBps)
		if report.SpeedReduction > 50 {
			log.Printf("  Speed reduction: %.1f%% ✓", report.SpeedReduction)
		}
		return 0
	}

	log.Println("\n✗ Rate limit test FAILED!")
	log.Printf("  Baseline: %.2f MB/s, Limited: %.2f MB/s (%.1f%% of limit)", 
		report.BaselineRateMBps, report.ActualRateMBps, report.RateAccuracy)
	log.Println("  Rate limit not effective - actual rate exceeds expected limit")
	return 1
}

func printRateLimitReport(report *RateLimitTestReport) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 68))
	fmt.Println("                   Rate Limit Test Report")
	fmt.Println(strings.Repeat("=", 68))
	
	// Baseline info
	fmt.Println("【Baseline (No Limit)】")
	fmt.Printf("  Throughput:       %.2f MB/s (%d bytes/s)\n", report.BaselineRateMBps, report.BaselineRateBps)
	fmt.Println()
	
	// Rate limited info
	fmt.Println("【With Rate Limit】")
	fmt.Printf("  Expected Rate:    %.2f MB/s (%d bytes/s)\n", report.ExpectedRateMBps, report.ExpectedRateBps)
	fmt.Printf("  Actual Rate:      %.2f MB/s (%d bytes/s)\n", report.ActualRateMBps, report.ActualRateBps)
	fmt.Printf("  Rate Accuracy:    %.1f%% of limit\n", report.RateAccuracy)
	fmt.Printf("  Speed Reduction:  %.1f%% from baseline\n", report.SpeedReduction)
	fmt.Println()
	
	// Test details
	fmt.Println("【Test Details】")
	fmt.Printf("  Duration:         %v\n", report.Duration)
	fmt.Printf("  Bytes Transferred: %s\n", formatBytesForReport(report.BytesTransferred))
	
	fmt.Println(strings.Repeat("-", 68))
	
	// Analysis
	fmt.Println("【Analysis】")
	
	// Check if rate limiting is effective (main criteria: not exceeding limit)
	if report.RateLimitEffective {
		fmt.Println("  Rate Limiting:    ✓ EFFECTIVE (actual ≤ expected)")
	} else {
		fmt.Println("  Rate Limiting:    ✗ NOT EFFECTIVE (actual > expected)")
	}
	
	// Check accuracy (secondary criteria)
	if report.WithinTolerance {
		fmt.Printf("  Accuracy:         ✓ GOOD (%.0f%% of limit)\n", report.RateAccuracy)
	} else if report.RateAccuracy > 120 {
		fmt.Printf("  Accuracy:         ✗ EXCEEDS LIMIT (%.0f%%)\n", report.RateAccuracy)
	} else {
		fmt.Printf("  Accuracy:         ✓ OK (%.0f%% - rate shared by both directions)\n", report.RateAccuracy)
	}
	
	// Check speed reduction if baseline > limit
	if report.BaselineRateBps > report.ExpectedRateBps {
		if report.SpeedReduction > 50 {
			fmt.Printf("  Speed Reduction:  ✓ %.1f%% reduction from baseline\n", report.SpeedReduction)
		} else if report.SpeedReduction > 0 {
			fmt.Printf("  Speed Reduction:  ⚠ Only %.1f%% reduction\n", report.SpeedReduction)
		} else {
			fmt.Println("  Speed Reduction:  ✗ No reduction (rate limit not working)")
		}
	}
	
	// Note about bidirectional rate sharing
	if report.RateAccuracy < 70 && report.RateLimitEffective {
		fmt.Println()
		fmt.Println("  Note: Rate limit is shared between both directions (send/receive).")
		fmt.Println("        Single direction measures ~50-70% of total limit.")
	}
	
	fmt.Println(strings.Repeat("=", 68))
}

func formatBytesForReport(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// RunSingleModeTests runs tests for a single mode
func RunSingleModeTests(cfg *Config) int {
	log.Println("========================================")
	log.Printf("  NatSvr Single Mode Test: %s", cfg.Mode)
	log.Println("========================================")

	var runner *TestRunner
	if cfg.Server != "" && cfg.Token != "" {
		runner = NewTestRunnerWithExternal(cfg.WorkDir, cfg.Server, cfg.Token)
		log.Printf("Using external server: %s", cfg.Server)
	} else {
		runner = NewTestRunner(cfg.WorkDir)
		log.Println("Using internal test server")
	}

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, cleaning up...")
		runner.Cleanup()
		os.Exit(1)
	}()

	if !cfg.SkipCleanup {
		defer runner.Cleanup()
	}

	// Find matching mode
	modeName := normalizeModeName(cfg.Mode)
	
	// Setup for single mode
	if err := runner.SetupForSingleMode(modeName); err != nil {
		log.Printf("Failed to setup environment: %v", err)
		return 1
	}

	// Run the test
	modeReport, err := runner.RunSingleModeTest(modeName)
	if err != nil {
		log.Printf("Test execution failed: %v", err)
		return 1
	}

	// Create full report from single mode
	report := &FullTestReport{
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Modes:     map[string]*ModeTestReport{modeName: modeReport},
	}
	report.Duration = report.EndTime.Sub(report.StartTime)

	// Print report
	report.PrintReport()

	// Save reports if requested
	saveReports(cfg, report)

	// Print server stats
	printServerStats(runner)

	// Determine result
	if modeReport.Error != "" {
		log.Printf("\n✗ Test for mode %s FAILED: %s", modeName, modeReport.Error)
		return 1
	}

	if modeReport.Consistency != nil {
		successRate := float64(modeReport.Consistency.SuccessMessages) / float64(modeReport.Consistency.TotalMessages) * 100
		if successRate < 99.0 {
			log.Printf("\n✗ Test for mode %s FAILED: consistency rate %.2f%%", modeName, successRate)
			return 1
		}
	}

	log.Printf("\n✓ Test for mode %s PASSED!", modeName)
	return 0
}

// normalizeModeName converts short mode names to full names
func normalizeModeName(mode string) string {
	mode = strings.ToLower(mode)
	switch mode {
	case "remote", "1", "mode1":
		return "Mode1-Remote"
	case "cloud-self", "cloudself", "2", "mode2":
		return "Mode2-CloudSelf"
	case "agent-cloud", "agentcloud", "3", "mode3":
		return "Mode3-AgentCloud"
	case "p2p", "agent-agent", "4", "mode4":
		return "Mode4-P2P"
	default:
		return mode
	}
}

// RunIntegrationTests runs all integration tests
func RunIntegrationTests(cfg *Config) int {
	log.Println("========================================")
	log.Println("  NatSvr Integration Test Suite")
	log.Println("========================================")

	var runner *TestRunner
	if cfg.Server != "" && cfg.Token != "" {
		runner = NewTestRunnerWithExternal(cfg.WorkDir, cfg.Server, cfg.Token)
		log.Printf("Using external server: %s", cfg.Server)
	} else {
		runner = NewTestRunner(cfg.WorkDir)
		log.Println("Using internal test server")
	}

	// Setup signal handler for cleanup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, cleaning up...")
		runner.Cleanup()
		os.Exit(1)
	}()

	// Ensure cleanup on exit
	if !cfg.SkipCleanup {
		defer runner.Cleanup()
	}

	// Setup environment
	if err := runner.SetupEnvironment(); err != nil {
		log.Printf("Failed to setup environment: %v", err)
		return 1
	}

	// Run all tests
	report, err := runner.RunAllTests()
	if err != nil {
		log.Printf("Test execution failed: %v", err)
		return 1
	}

	// Print report
	report.PrintReport()
	report.PrintComparisonTable()

	// Save reports if requested
	saveReports(cfg, report)

	// Print server stats
	printServerStats(runner)

	// Determine exit code
	summary := report.GetSummary()
	if summary.OverallSuccess {
		log.Println("\n✓ All integration tests passed!")
		return 0
	}

	log.Println("\n✗ Some integration tests failed!")
	return 1
}

func saveReports(cfg *Config, report *FullTestReport) {
	if cfg.SaveJSON {
		jsonPath := filepath.Join(cfg.OutputDir, "integration-test-report.json")
		if err := report.SaveJSON(jsonPath); err != nil {
			log.Printf("Failed to save JSON report: %v", err)
		} else {
			log.Printf("JSON report saved to: %s", jsonPath)
		}
	}

	if cfg.SaveMarkdown {
		mdPath := filepath.Join(cfg.OutputDir, "integration-test-report.md")
		if err := report.SaveMarkdown(mdPath); err != nil {
			log.Printf("Failed to save Markdown report: %v", err)
		} else {
			log.Printf("Markdown report saved to: %s", mdPath)
		}
	}
}

func printServerStats(runner *TestRunner) {
	log.Println("\nTest Server Statistics:")
	for i, stats := range runner.GetServerStats() {
		log.Printf("  Server %d:", i+1)
		log.Printf("    Connections: %d total, %d active", stats.ConnectionsTotal, stats.ConnectionsActive)
		log.Printf("    Messages: %d received, %d sent", stats.MessagesReceived, stats.MessagesSent)
		log.Printf("    Bytes: %d received, %d sent", stats.BytesReceived, stats.BytesSent)
		if stats.ChecksumErrors > 0 {
			log.Printf("    Checksum Errors: %d", stats.ChecksumErrors)
		}
	}
}

// findProjectRoot tries to find the project root directory
func findProjectRoot(start string) string {
	dir := start
	for {
		// Check for go.mod file
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			return ""
		}
		dir = parent
	}
}

// QuickTest runs a quick connectivity test for a single mode
func QuickTest(address string) error {
	client := NewTestClient(address)
	if err := client.Connect(); err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	defer client.Close()

	result := client.Ping()
	if !result.Success {
		return fmt.Errorf("ping failed: %v", result.Error)
	}

	log.Printf("Quick test passed! RTT: %v", result.Latency)
	return nil
}

// BenchmarkMode runs benchmark tests for a specific mode
func BenchmarkMode(address string, duration time.Duration) (*ModeTestReport, error) {
	report := &ModeTestReport{
		ModeName: "Benchmark",
	}

	client := NewTestClient(address)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("connect failed: %v", err)
	}
	defer client.Close()

	// Run latency test
	log.Println("Running latency benchmark...")
	latencyResult, _ := client.RunLatencyTest(1000, 64)
	report.Latency = latencyResult

	// Run throughput test
	log.Println("Running throughput benchmark...")
	throughputResult, _ := client.RunThroughputTest(duration, 32*1024)
	report.Throughput = throughputResult

	return report, nil
}
