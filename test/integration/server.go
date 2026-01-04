package integration

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// Protocol format:
// [4 bytes: length][4 bytes: sequence][4 bytes: checksum][N bytes: data]
// Total header size: 12 bytes

const (
	HeaderSize     = 12
	MaxMessageSize = 64 * 1024 // 64KB max payload
)

// Message represents a test protocol message
type Message struct {
	Length   uint32
	Sequence uint32
	Checksum uint32
	Data     []byte
}

// Encode serializes the message to bytes
func (m *Message) Encode() []byte {
	buf := make([]byte, HeaderSize+len(m.Data))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(m.Data)))
	binary.BigEndian.PutUint32(buf[4:8], m.Sequence)
	binary.BigEndian.PutUint32(buf[8:12], crc32.ChecksumIEEE(m.Data))
	copy(buf[12:], m.Data)
	return buf
}

// DecodeMessage reads a message from a reader
func DecodeMessage(r io.Reader) (*Message, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header[0:4])
	sequence := binary.BigEndian.Uint32(header[4:8])
	checksum := binary.BigEndian.Uint32(header[8:12])

	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d", length)
	}

	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	}

	return &Message{
		Length:   length,
		Sequence: sequence,
		Checksum: checksum,
		Data:     data,
	}, nil
}

// ValidateChecksum validates the message checksum
func (m *Message) ValidateChecksum() bool {
	expected := crc32.ChecksumIEEE(m.Data)
	return m.Checksum == expected
}

// NewMessage creates a new message with computed checksum
func NewMessage(sequence uint32, data []byte) *Message {
	return &Message{
		Length:   uint32(len(data)),
		Sequence: sequence,
		Checksum: crc32.ChecksumIEEE(data),
		Data:     data,
	}
}

// TestServer is an echo server with checksum validation
type TestServer struct {
	port       int
	listener   net.Listener
	running    bool
	mu         sync.Mutex
	stats      ServerStats
	onMessage  func(conn net.Conn, msg *Message) // Optional callback for custom handling
	echoMode   bool                              // If true, echo back messages
}

// ServerStats tracks server statistics
type ServerStats struct {
	ConnectionsTotal   int64
	ConnectionsActive  int64
	MessagesReceived   int64
	MessagesSent       int64
	BytesReceived      int64
	BytesSent          int64
	ChecksumErrors     int64
}

// NewTestServer creates a new test server
func NewTestServer(port int) *TestServer {
	return &TestServer{
		port:     port,
		echoMode: true,
	}
}

// SetEchoMode enables or disables echo mode
func (s *TestServer) SetEchoMode(echo bool) {
	s.echoMode = echo
}

// SetOnMessage sets a custom message handler
func (s *TestServer) SetOnMessage(handler func(conn net.Conn, msg *Message)) {
	s.onMessage = handler
}

// Start starts the server
func (s *TestServer) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.port, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	log.Printf("[TestServer] Started on port %d", s.port)

	go s.acceptLoop()
	return nil
}

// Stop stops the server
func (s *TestServer) Stop() {
	s.mu.Lock()
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()
	log.Printf("[TestServer] Stopped on port %d", s.port)
}

// GetStats returns server statistics
func (s *TestServer) GetStats() ServerStats {
	return ServerStats{
		ConnectionsTotal:  atomic.LoadInt64(&s.stats.ConnectionsTotal),
		ConnectionsActive: atomic.LoadInt64(&s.stats.ConnectionsActive),
		MessagesReceived:  atomic.LoadInt64(&s.stats.MessagesReceived),
		MessagesSent:      atomic.LoadInt64(&s.stats.MessagesSent),
		BytesReceived:     atomic.LoadInt64(&s.stats.BytesReceived),
		BytesSent:         atomic.LoadInt64(&s.stats.BytesSent),
		ChecksumErrors:    atomic.LoadInt64(&s.stats.ChecksumErrors),
	}
}

func (s *TestServer) acceptLoop() {
	for {
		s.mu.Lock()
		running := s.running
		listener := s.listener
		s.mu.Unlock()

		if !running {
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("[TestServer] Accept error: %v", err)
			}
			continue
		}

		atomic.AddInt64(&s.stats.ConnectionsTotal, 1)
		atomic.AddInt64(&s.stats.ConnectionsActive, 1)

		go s.handleConnection(conn)
	}
}

func (s *TestServer) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt64(&s.stats.ConnectionsActive, -1)
	}()

	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()

		if !running {
			return
		}

		msg, err := DecodeMessage(conn)
		if err != nil {
			if err != io.EOF {
				// Only log non-EOF errors
				if s.running {
					log.Printf("[TestServer] Read error: %v", err)
				}
			}
			return
		}

		atomic.AddInt64(&s.stats.MessagesReceived, 1)
		atomic.AddInt64(&s.stats.BytesReceived, int64(len(msg.Data)+HeaderSize))

		// Validate checksum
		if !msg.ValidateChecksum() {
			atomic.AddInt64(&s.stats.ChecksumErrors, 1)
			log.Printf("[TestServer] Checksum error for sequence %d", msg.Sequence)
			continue
		}

		// Custom handler if set
		if s.onMessage != nil {
			s.onMessage(conn, msg)
		}

		// Echo mode: send back the same message
		if s.echoMode {
			encoded := msg.Encode()
			_, err := conn.Write(encoded)
			if err != nil {
				log.Printf("[TestServer] Write error: %v", err)
				return
			}
			atomic.AddInt64(&s.stats.MessagesSent, 1)
			atomic.AddInt64(&s.stats.BytesSent, int64(len(encoded)))
		}
	}
}

// Port returns the server's listening port
func (s *TestServer) Port() int {
	return s.port
}

