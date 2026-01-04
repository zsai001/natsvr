package cloud

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	bytesPerSecond int64
	tokens         int64
	maxTokens      int64
	lastRefill     time.Time
	mu             sync.Mutex
}

// NewRateLimiter creates a new rate limiter
// bytesPerSecond: 0 means unlimited
func NewRateLimiter(bytesPerSecond int64) *RateLimiter {
	if bytesPerSecond <= 0 {
		return nil // nil means unlimited
	}
	// Start with partial bucket (0.5 second worth) to limit initial burst
	// Max tokens = 1 second worth, allowing small burst but staying close to rate
	return &RateLimiter{
		bytesPerSecond: bytesPerSecond,
		tokens:         bytesPerSecond / 2, // Start with half second worth
		maxTokens:      bytesPerSecond,     // Allow burst of 1 second max
		lastRefill:     time.Now(),
	}
}

// Wait blocks until n bytes can be consumed
// This uses a simple token bucket algorithm with proper concurrency handling
func (r *RateLimiter) Wait(n int64) {
	if r == nil || r.bytesPerSecond <= 0 {
		return
	}

	for {
		r.mu.Lock()
		
		// Refill tokens based on elapsed time
		r.refill()

		// If we have enough tokens, consume and return immediately
		if r.tokens >= n {
			r.tokens -= n
			r.mu.Unlock()
			return
		}

		// Not enough tokens - calculate how long to wait for enough tokens
		needed := n - r.tokens
		waitTime := time.Duration(float64(needed)/float64(r.bytesPerSecond)*float64(time.Second)) + time.Millisecond
		
		r.mu.Unlock()
		
		// Sleep and retry
		time.Sleep(waitTime)
	}
}

func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)
	
	if elapsed <= 0 {
		return
	}
	
	r.lastRefill = now
	tokensToAdd := int64(float64(r.bytesPerSecond) * elapsed.Seconds())
	r.tokens += tokensToAdd
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
}

// RateLimitedReader wraps a reader with rate limiting
type RateLimitedReader struct {
	reader  io.Reader
	limiter *RateLimiter
}

func NewRateLimitedReader(r io.Reader, limiter *RateLimiter) io.Reader {
	if limiter == nil {
		return r
	}
	return &RateLimitedReader{reader: r, limiter: limiter}
}

func (r *RateLimitedReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 && r.limiter != nil {
		r.limiter.Wait(int64(n))
	}
	return
}

// RateLimitedWriter wraps a writer with rate limiting
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *RateLimiter
}

func NewRateLimitedWriter(w io.Writer, limiter *RateLimiter) io.Writer {
	if limiter == nil {
		return w
	}
	return &RateLimitedWriter{writer: w, limiter: limiter}
}

func (w *RateLimitedWriter) Write(p []byte) (n int, err error) {
	if w.limiter != nil {
		w.limiter.Wait(int64(len(p)))
	}
	return w.writer.Write(p)
}

// TrafficCounter tracks traffic bytes and speed
type TrafficCounter struct {
	totalBytes     int64
	bytesInWindow  int64
	windowStart    time.Time
	currentSpeed   float64 // bytes per second
	mu             sync.Mutex
}

func NewTrafficCounter() *TrafficCounter {
	return &TrafficCounter{
		windowStart: time.Now(),
	}
}

func (t *TrafficCounter) Add(n int64) {
	atomic.AddInt64(&t.totalBytes, n)
	atomic.AddInt64(&t.bytesInWindow, n)
}

func (t *TrafficCounter) Total() int64 {
	return atomic.LoadInt64(&t.totalBytes)
}

func (t *TrafficCounter) Speed() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	elapsed := time.Since(t.windowStart).Seconds()
	if elapsed >= 1.0 {
		t.currentSpeed = float64(atomic.LoadInt64(&t.bytesInWindow)) / elapsed
		atomic.StoreInt64(&t.bytesInWindow, 0)
		t.windowStart = time.Now()
	}
	return t.currentSpeed
}

// GlobalStats tracks global traffic statistics
type GlobalStats struct {
	TxBytes   int64
	RxBytes   int64
	txCounter *TrafficCounter
	rxCounter *TrafficCounter
}

func NewGlobalStats() *GlobalStats {
	return &GlobalStats{
		txCounter: NewTrafficCounter(),
		rxCounter: NewTrafficCounter(),
	}
}

func (s *GlobalStats) AddTx(n int64) {
	atomic.AddInt64(&s.TxBytes, n)
	s.txCounter.Add(n)
}

func (s *GlobalStats) AddRx(n int64) {
	atomic.AddInt64(&s.RxBytes, n)
	s.rxCounter.Add(n)
}

func (s *GlobalStats) GetStats() (txBytes, rxBytes int64, txSpeed, rxSpeed float64) {
	txBytes = atomic.LoadInt64(&s.TxBytes)
	rxBytes = atomic.LoadInt64(&s.RxBytes)
	txSpeed = s.txCounter.Speed()
	rxSpeed = s.rxCounter.Speed()
	return
}

