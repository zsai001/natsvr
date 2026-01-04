package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TestClient is a client for testing the forwarding system
type TestClient struct {
	address string
	conn    net.Conn
	mu      sync.Mutex
}

// NewTestClient creates a new test client
func NewTestClient(address string) *TestClient {
	return &TestClient{
		address: address,
	}
}

// Connect establishes a connection to the server
func (c *TestClient) Connect() error {
	conn, err := net.DialTimeout("tcp", c.address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.address, err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	return nil
}

// Close closes the connection
func (c *TestClient) Close() {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()
}

// SendMessage sends a message and waits for echo response
func (c *TestClient) SendMessage(msg *Message) (*Message, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Send message
	encoded := msg.Encode()
	if _, err := conn.Write(encoded); err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}

	// Read response
	response, err := DecodeMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	return response, nil
}

// SendMessageWithTimeout sends a message with timeout
func (c *TestClient) SendMessageWithTimeout(msg *Message, timeout time.Duration) (*Message, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Set deadline
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	return c.SendMessage(msg)
}

// ConsistencyTestResult holds results of consistency test
type ConsistencyTestResult struct {
	TotalMessages    int
	SuccessMessages  int
	ChecksumErrors   int
	DataMismatch     int
	SequenceMismatch int
	Errors           []error
}

// RunConsistencyTest runs a data consistency test
func (c *TestClient) RunConsistencyTest(messageCount int, dataSize int) (*ConsistencyTestResult, error) {
	result := &ConsistencyTestResult{}

	for i := 0; i < messageCount; i++ {
		// Generate random data
		data := make([]byte, dataSize)
		if _, err := rand.Read(data); err != nil {
			return nil, fmt.Errorf("failed to generate random data: %v", err)
		}

		msg := NewMessage(uint32(i), data)
		response, err := c.SendMessageWithTimeout(msg, 30*time.Second)
		result.TotalMessages++

		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		}

		// Validate response
		if !response.ValidateChecksum() {
			result.ChecksumErrors++
			continue
		}

		if response.Sequence != msg.Sequence {
			result.SequenceMismatch++
			continue
		}

		if !bytes.Equal(response.Data, msg.Data) {
			result.DataMismatch++
			continue
		}

		result.SuccessMessages++
	}

	return result, nil
}

// LatencyTestResult holds results of latency test
type LatencyTestResult struct {
	SampleCount int
	MinLatency  time.Duration
	MaxLatency  time.Duration
	AvgLatency  time.Duration
	P50Latency  time.Duration
	P95Latency  time.Duration
	P99Latency  time.Duration
	Latencies   []time.Duration
}

// RunLatencyTest runs a latency (RTT) test
func (c *TestClient) RunLatencyTest(sampleCount int, dataSize int) (*LatencyTestResult, error) {
	result := &LatencyTestResult{
		Latencies: make([]time.Duration, 0, sampleCount),
	}

	data := make([]byte, dataSize)
	rand.Read(data)

	for i := 0; i < sampleCount; i++ {
		msg := NewMessage(uint32(i), data)

		start := time.Now()
		response, err := c.SendMessageWithTimeout(msg, 30*time.Second)
		latency := time.Since(start)

		if err != nil {
			continue
		}

		if !response.ValidateChecksum() || response.Sequence != msg.Sequence {
			continue
		}

		result.Latencies = append(result.Latencies, latency)
	}

	result.SampleCount = len(result.Latencies)
	if result.SampleCount > 0 {
		result.calculateStats()
	}

	return result, nil
}

func (r *LatencyTestResult) calculateStats() {
	if len(r.Latencies) == 0 {
		return
	}

	// Sort latencies for percentile calculation
	sorted := make([]time.Duration, len(r.Latencies))
	copy(sorted, r.Latencies)
	sortDurations(sorted)

	r.MinLatency = sorted[0]
	r.MaxLatency = sorted[len(sorted)-1]

	// Calculate average
	var total time.Duration
	for _, l := range sorted {
		total += l
	}
	r.AvgLatency = total / time.Duration(len(sorted))

	// Calculate percentiles
	r.P50Latency = sorted[len(sorted)*50/100]
	r.P95Latency = sorted[len(sorted)*95/100]
	r.P99Latency = sorted[len(sorted)*99/100]
}

func sortDurations(durations []time.Duration) {
	// Simple bubble sort for small arrays
	n := len(durations)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if durations[j] > durations[j+1] {
				durations[j], durations[j+1] = durations[j+1], durations[j]
			}
		}
	}
}

// ThroughputTestResult holds results of throughput test
type ThroughputTestResult struct {
	Duration     time.Duration
	BytesSent    int64
	BytesRecv    int64
	MessagesSent int64
	MessagesRecv int64
	SendRate     float64 // MB/s
	RecvRate     float64 // MB/s
}

// RunThroughputTest runs a throughput test for the specified duration
func (c *TestClient) RunThroughputTest(duration time.Duration, dataSize int) (*ThroughputTestResult, error) {
	result := &ThroughputTestResult{}

	data := make([]byte, dataSize)
	rand.Read(data)

	start := time.Now()
	deadline := start.Add(duration)
	sequence := uint32(0)

	for time.Now().Before(deadline) {
		msg := NewMessage(sequence, data)
		sequence++

		encoded := msg.Encode()
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()

		if conn == nil {
			return nil, fmt.Errorf("connection lost")
		}

		conn.SetDeadline(deadline.Add(5 * time.Second))
		if _, err := conn.Write(encoded); err != nil {
			break
		}
		result.BytesSent += int64(len(encoded))
		result.MessagesSent++

		// Read response
		response, err := DecodeMessage(conn)
		if err != nil {
			break
		}
		result.BytesRecv += int64(len(response.Data) + HeaderSize)
		result.MessagesRecv++
	}

	result.Duration = time.Since(start)
	seconds := result.Duration.Seconds()
	if seconds > 0 {
		result.SendRate = float64(result.BytesSent) / seconds / 1024 / 1024
		result.RecvRate = float64(result.BytesRecv) / seconds / 1024 / 1024
	}

	return result, nil
}

// StressTestResult holds results of stress test
type StressTestResult struct {
	Duration         time.Duration
	TotalConnections int
	SuccessConns     int
	FailedConns      int
	TotalMessages    int64
	SuccessMessages  int64
	FailedMessages   int64
	TotalBytes       int64
	Throughput       float64 // MB/s
}

// RunStressTest runs a concurrent stress test
func RunStressTest(address string, concurrency int, duration time.Duration, dataSize int) (*StressTestResult, error) {
	result := &StressTestResult{
		TotalConnections: concurrency,
	}

	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(duration)

	var successConns int64
	var failedConns int64
	var totalMessages int64
	var successMessages int64
	var failedMessages int64
	var totalBytes int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := NewTestClient(address)
			if err := client.Connect(); err != nil {
				atomic.AddInt64(&failedConns, 1)
				return
			}
			defer client.Close()
			atomic.AddInt64(&successConns, 1)

			data := make([]byte, dataSize)
			rand.Read(data)
			sequence := uint32(0)

			for time.Now().Before(deadline) {
				msg := NewMessage(sequence, data)
				sequence++

				atomic.AddInt64(&totalMessages, 1)

				response, err := client.SendMessageWithTimeout(msg, 5*time.Second)
				if err != nil {
					atomic.AddInt64(&failedMessages, 1)
					continue
				}

				if response.ValidateChecksum() && bytes.Equal(response.Data, msg.Data) {
					atomic.AddInt64(&successMessages, 1)
					atomic.AddInt64(&totalBytes, int64(len(msg.Data)+HeaderSize)*2)
				} else {
					atomic.AddInt64(&failedMessages, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	result.Duration = time.Since(start)
	result.SuccessConns = int(successConns)
	result.FailedConns = int(failedConns)
	result.TotalMessages = totalMessages
	result.SuccessMessages = successMessages
	result.FailedMessages = failedMessages
	result.TotalBytes = totalBytes

	if result.Duration.Seconds() > 0 {
		result.Throughput = float64(result.TotalBytes) / result.Duration.Seconds() / 1024 / 1024
	}

	return result, nil
}

// StreamTestResult holds results of streaming test
type StreamTestResult struct {
	BytesSent     int64
	BytesReceived int64
	Duration      time.Duration
	SendRate      float64 // MB/s
	RecvRate      float64 // MB/s
	Matches       bool
}

// RunStreamTest runs a large data streaming test
func (c *TestClient) RunStreamTest(totalBytes int64) (*StreamTestResult, error) {
	result := &StreamTestResult{}

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Generate test data in chunks
	chunkSize := int64(32 * 1024) // 32KB chunks
	sentData := make([]byte, 0, totalBytes)
	receivedData := make([]byte, 0, totalBytes)

	start := time.Now()
	sequence := uint32(0)

	for result.BytesSent < totalBytes {
		remaining := totalBytes - result.BytesSent
		size := chunkSize
		if remaining < chunkSize {
			size = remaining
		}

		data := make([]byte, size)
		rand.Read(data)
		sentData = append(sentData, data...)

		msg := NewMessage(sequence, data)
		sequence++

		response, err := c.SendMessageWithTimeout(msg, 30*time.Second)
		if err != nil {
			return nil, fmt.Errorf("send error at %d bytes: %v", result.BytesSent, err)
		}

		receivedData = append(receivedData, response.Data...)
		result.BytesSent += int64(len(data))
		result.BytesReceived += int64(len(response.Data))
	}

	result.Duration = time.Since(start)
	result.Matches = bytes.Equal(sentData, receivedData)

	if result.Duration.Seconds() > 0 {
		result.SendRate = float64(result.BytesSent) / result.Duration.Seconds() / 1024 / 1024
		result.RecvRate = float64(result.BytesReceived) / result.Duration.Seconds() / 1024 / 1024
	}

	return result, nil
}

// PingResult holds ping test result
type PingResult struct {
	Success bool
	Latency time.Duration
	Error   error
}

// Ping sends a single ping message
func (c *TestClient) Ping() *PingResult {
	data := []byte("PING")
	msg := NewMessage(0, data)

	start := time.Now()
	response, err := c.SendMessageWithTimeout(msg, 5*time.Second)
	latency := time.Since(start)

	if err != nil {
		return &PingResult{Success: false, Error: err}
	}

	if !response.ValidateChecksum() {
		return &PingResult{Success: false, Error: io.ErrUnexpectedEOF}
	}

	return &PingResult{Success: true, Latency: latency}
}

// RateLimitTestResult holds results of rate limit test
type RateLimitTestResult struct {
	ExpectedRate   float64       // Expected rate in bytes/second
	ActualRate     float64       // Actual measured rate in bytes/second
	Duration       time.Duration // Test duration
	BytesTransfer  int64         // Total bytes transferred
	RateAccuracy   float64       // Accuracy percentage (actual/expected * 100)
	WithinTolerance bool         // Whether actual rate is within tolerance of expected
	Tolerance      float64       // Tolerance percentage used (e.g., 20%)
}

// RunRateLimitTest tests if rate limiting is working correctly
// Uses pipelined async sending to measure true throughput
// expectedRateBps: expected rate limit in bytes per second
// testDuration: how long to run the test
// tolerance: acceptable deviation from expected rate (0.2 = 20%)
func (c *TestClient) RunRateLimitTest(expectedRateBps int64, testDuration time.Duration, tolerance float64) (*RateLimitTestResult, error) {
	result := &RateLimitTestResult{
		ExpectedRate: float64(expectedRateBps),
		Tolerance:    tolerance * 100,
	}

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Use 32KB chunks for better throughput measurement
	chunkSize := 32 * 1024
	data := make([]byte, chunkSize)
	rand.Read(data)

	var sentBytes int64
	var recvBytes int64
	
	done := make(chan struct{})
	
	// Start time
	start := time.Now()
	deadline := start.Add(testDuration)
	
	conn.SetDeadline(deadline.Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Sender goroutine - send as fast as possible
	go func() {
		sequence := uint32(0)
		for time.Now().Before(deadline) {
			msg := NewMessage(sequence, data)
			sequence++

			encoded := msg.Encode()
			n, err := conn.Write(encoded)
			if err != nil {
				break
			}
			atomic.AddInt64(&sentBytes, int64(n))
		}
	}()

	// Receiver goroutine - receive responses
	go func() {
		defer close(done)
		for time.Now().Before(deadline) {
			response, err := DecodeMessage(conn)
			if err != nil {
				break
			}
			atomic.AddInt64(&recvBytes, int64(len(response.Data)+HeaderSize))
		}
	}()

	// Wait for test duration
	<-time.After(testDuration)
	
	// Give some time for pending data
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}

	result.Duration = time.Since(start)
	finalSent := atomic.LoadInt64(&sentBytes)
	finalRecv := atomic.LoadInt64(&recvBytes)
	result.BytesTransfer = finalSent + finalRecv

	// Calculate actual rate based on received bytes (this reflects the rate-limited throughput)
	// The rate limiter is applied on the server side, so received bytes reflect the actual limited rate
	seconds := result.Duration.Seconds()
	if seconds > 0 {
		// Use received bytes as the measure - this is what actually made it through the rate limiter
		result.ActualRate = float64(finalRecv) / seconds
	}

	// Calculate accuracy
	if result.ExpectedRate > 0 {
		result.RateAccuracy = result.ActualRate / result.ExpectedRate * 100
		
		// Rate limiter should cap traffic at the expected rate
		// Allow 20% below and tolerance above (for burst)
		lowerBound := result.ExpectedRate * 0.8  // At least 80% of expected
		upperBound := result.ExpectedRate * (1 + tolerance) // Allow some overshoot due to burst
		result.WithinTolerance = result.ActualRate >= lowerBound && result.ActualRate <= upperBound
	}

	return result, nil
}

