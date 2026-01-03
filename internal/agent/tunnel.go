package agent

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/natsvr/natsvr/internal/protocol"
)

// TCPTunnel handles TCP tunnel connections
type TCPTunnel struct {
	client     *Client
	tunnelID   uint32
	targetHost string
	targetPort uint16
	conn       net.Conn
	connMu     sync.Mutex
	closed     bool
}

// NewTCPTunnel creates a new TCP tunnel
func NewTCPTunnel(client *Client, tunnelID uint32, targetHost string, targetPort uint16) *TCPTunnel {
	return &TCPTunnel{
		client:     client,
		tunnelID:   tunnelID,
		targetHost: targetHost,
		targetPort: targetPort,
	}
}

// Start connects to the target and starts forwarding
func (t *TCPTunnel) Start() error {
	addr := fmt.Sprintf("%s:%d", t.targetHost, t.targetPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	// Start reading from target
	go t.readFromTarget()

	return nil
}

// Stop closes the tunnel
func (t *TCPTunnel) Stop() {
	t.connMu.Lock()
	t.closed = true
	if t.conn != nil {
		t.conn.Close()
	}
	t.connMu.Unlock()
}

// HandleData writes data to the target
func (t *TCPTunnel) HandleData(data []byte) error {
	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()

	if conn == nil {
		return fmt.Errorf("connection closed")
	}

	log.Printf("Tunnel %d: writing %d bytes to target", t.tunnelID, len(data))
	_, err := conn.Write(data)
	return err
}

func (t *TCPTunnel) readFromTarget() {
	buf := make([]byte, 32768)
	log.Printf("Tunnel %d: starting to read from target %s:%d", t.tunnelID, t.targetHost, t.targetPort)

	for {
		t.connMu.Lock()
		conn := t.conn
		closed := t.closed
		t.connMu.Unlock()

		if closed || conn == nil {
			log.Printf("Tunnel %d: connection closed or nil", t.tunnelID)
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			if !t.closed {
				log.Printf("Tunnel %d: read from target error: %v", t.tunnelID, err)
				t.client.SendClose(t.tunnelID)
			}
			return
		}

		log.Printf("Tunnel %d: read %d bytes from target, sending to cloud", t.tunnelID, n)
		if err := t.client.SendData(t.tunnelID, buf[:n]); err != nil {
			log.Printf("Tunnel %d: send data error: %v", t.tunnelID, err)
			return
		}
	}
}

// UDPTunnel handles UDP tunnel connections
type UDPTunnel struct {
	client     *Client
	tunnelID   uint32
	targetHost string
	targetPort uint16
	conn       *net.UDPConn
	connMu     sync.Mutex
	closed     bool
}

// NewUDPTunnel creates a new UDP tunnel
func NewUDPTunnel(client *Client, tunnelID uint32, targetHost string, targetPort uint16) *UDPTunnel {
	return &UDPTunnel{
		client:     client,
		tunnelID:   tunnelID,
		targetHost: targetHost,
		targetPort: targetPort,
	}
}

// Start initializes the UDP connection
func (t *UDPTunnel) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", t.targetHost, t.targetPort))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	// Start reading from target
	go t.readFromTarget()

	return nil
}

// Stop closes the tunnel
func (t *UDPTunnel) Stop() {
	t.connMu.Lock()
	t.closed = true
	if t.conn != nil {
		t.conn.Close()
	}
	t.connMu.Unlock()
}

// HandleData writes data to the target
func (t *UDPTunnel) HandleData(data []byte) error {
	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()

	if conn == nil {
		return fmt.Errorf("connection closed")
	}

	_, err := conn.Write(data)
	return err
}

// HandleUDPData handles UDP data with addressing info
func (t *UDPTunnel) HandleUDPData(payload *protocol.UDPDataPayload) {
	t.HandleData(payload.Data)
}

func (t *UDPTunnel) readFromTarget() {
	buf := make([]byte, 65535)

	for {
		t.connMu.Lock()
		conn := t.conn
		closed := t.closed
		t.connMu.Unlock()

		if closed || conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !t.closed {
				log.Printf("UDP read error: %v", err)
			}
			return
		}

		// Send response back through tunnel
		udpPayload := protocol.EncodeUDPDataPayload(&protocol.UDPDataPayload{
			SourceAddr: t.targetHost,
			SourcePort: t.targetPort,
			Data:       buf[:n],
		})

		msg := protocol.NewMessage(protocol.MsgTypeUDPData, t.tunnelID, udpPayload)
		t.client.sendMessage(msg)
	}
}

// ICMPTunnel handles ICMP tunnel connections
type ICMPTunnel struct {
	client   *Client
	tunnelID uint32
	destAddr string
	closed   bool
	closeMu  sync.Mutex
}

// NewICMPTunnel creates a new ICMP tunnel
func NewICMPTunnel(client *Client, tunnelID uint32, destAddr string) *ICMPTunnel {
	return &ICMPTunnel{
		client:   client,
		tunnelID: tunnelID,
		destAddr: destAddr,
	}
}

// Start initializes the ICMP connection
func (t *ICMPTunnel) Start() error {
	// ICMP requires privileged access
	// For now, we just validate we can resolve the address
	_, err := net.ResolveIPAddr("ip", t.destAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %v", err)
	}
	return nil
}

// Stop closes the tunnel
func (t *ICMPTunnel) Stop() {
	t.closeMu.Lock()
	t.closed = true
	t.closeMu.Unlock()
}

// HandleData handles raw ICMP data
func (t *ICMPTunnel) HandleData(data []byte) error {
	// ICMP handling requires raw sockets - typically needs root privileges
	// This is a placeholder for ICMP forwarding
	log.Printf("ICMP data received for tunnel %d, length: %d", t.tunnelID, len(data))
	return nil
}

// HandleICMPData handles ICMP data with type info
func (t *ICMPTunnel) HandleICMPData(payload *protocol.ICMPDataPayload) {
	t.closeMu.Lock()
	closed := t.closed
	t.closeMu.Unlock()

	if closed {
		return
	}

	// For ICMP, we would need raw socket access
	// This typically requires root/admin privileges
	log.Printf("ICMP type %d to %s", payload.Type, payload.DestAddr)

	// Placeholder: In a full implementation, you would:
	// 1. Create a raw socket (requires elevated privileges)
	// 2. Send the ICMP packet
	// 3. Wait for response
	// 4. Forward response back through the tunnel
}

