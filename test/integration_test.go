package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/natsvr/natsvr/test/integration"
)

// TestIntegration runs the full integration test suite
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Find project root
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	projectRoot := findProjectRoot(cwd)
	if projectRoot == "" {
		t.Fatal("Could not find project root")
	}

	cfg := &integration.Config{
		WorkDir:      projectRoot,
		SaveJSON:     false,
		SaveMarkdown: false,
		OutputDir:    ".",
		Verbose:      testing.Verbose(),
		SkipCleanup:  false,
	}

	exitCode := integration.RunIntegrationTests(cfg)
	if exitCode != 0 {
		t.Fatalf("Integration tests failed with exit code %d", exitCode)
	}
}

// TestConsistency tests data consistency only
func TestConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// This test requires manual setup of cloud and agents
	address := os.Getenv("TEST_ADDRESS")
	if address == "" {
		t.Skip("TEST_ADDRESS not set")
	}

	client := integration.NewTestClient(address)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Test with different sizes
	sizes := []int{1, 1024, 32 * 1024}
	for _, size := range sizes {
		t.Run(sizeToName(size), func(t *testing.T) {
			result, err := client.RunConsistencyTest(100, size)
			if err != nil {
				t.Fatalf("Consistency test failed: %v", err)
			}

			if result.SuccessMessages != result.TotalMessages {
				t.Errorf("Not all messages successful: %d/%d",
					result.SuccessMessages, result.TotalMessages)
			}

			if result.ChecksumErrors > 0 {
				t.Errorf("Checksum errors: %d", result.ChecksumErrors)
			}

			if result.DataMismatch > 0 {
				t.Errorf("Data mismatch: %d", result.DataMismatch)
			}
		})
	}
}

// TestLatency tests RTT latency
func TestLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	address := os.Getenv("TEST_ADDRESS")
	if address == "" {
		t.Skip("TEST_ADDRESS not set")
	}

	client := integration.NewTestClient(address)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	result, err := client.RunLatencyTest(100, 64)
	if err != nil {
		t.Fatalf("Latency test failed: %v", err)
	}

	t.Logf("Latency: min=%v avg=%v max=%v p99=%v",
		result.MinLatency, result.AvgLatency, result.MaxLatency, result.P99Latency)

	if result.SampleCount < 50 {
		t.Errorf("Not enough samples: %d", result.SampleCount)
	}
}

// TestThroughput tests throughput
func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	address := os.Getenv("TEST_ADDRESS")
	if address == "" {
		t.Skip("TEST_ADDRESS not set")
	}

	client := integration.NewTestClient(address)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	result, err := client.RunThroughputTest(5*1000*1000*1000, 32*1024) // 5 seconds
	if err != nil {
		t.Fatalf("Throughput test failed: %v", err)
	}

	t.Logf("Throughput: send=%.2f MB/s recv=%.2f MB/s",
		result.SendRate, result.RecvRate)
}

// TestStress tests concurrent connections
func TestStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	address := os.Getenv("TEST_ADDRESS")
	if address == "" {
		t.Skip("TEST_ADDRESS not set")
	}

	result, err := integration.RunStressTest(address, 20, 3*1000*1000*1000, 1024) // 20 clients, 3s
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Stress: connections=%d/%d messages=%d/%d throughput=%.2f MB/s",
		result.SuccessConns, result.TotalConnections,
		result.SuccessMessages, result.TotalMessages,
		result.Throughput)

	if result.SuccessConns < result.TotalConnections/2 {
		t.Errorf("Too many failed connections: %d/%d", result.FailedConns, result.TotalConnections)
	}
}

// BenchmarkEcho benchmarks echo performance
func BenchmarkEcho(b *testing.B) {
	address := os.Getenv("TEST_ADDRESS")
	if address == "" {
		b.Skip("TEST_ADDRESS not set")
	}

	client := integration.NewTestClient(address)
	if err := client.Connect(); err != nil {
		b.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	data := make([]byte, 1024)
	msg := integration.NewMessage(0, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Sequence = uint32(i)
		_, err := client.SendMessage(msg)
		if err != nil {
			b.Fatalf("Send failed: %v", err)
		}
	}
}

func findProjectRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func sizeToName(size int) string {
	if size < 1024 {
		return "1B"
	} else if size < 1024*1024 {
		return "1KB"
	}
	return "32KB"
}

