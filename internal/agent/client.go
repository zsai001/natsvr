package agent

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/natsvr/natsvr/internal/protocol"
	"github.com/natsvr/natsvr/pkg/utils"
)

// Config holds agent configuration
type Config struct {
	ServerURL string
	Token     string
	Name      string
}

// Client is the agent client
type Client struct {
	config       *Config
	agentID      string
	conn         *websocket.Conn
	connMu       sync.Mutex
	tunnels      map[uint32]*TunnelHandler
	tunnelsMu    sync.RWMutex
	localProxies map[string]*P2PProxy // rule ID -> proxy
	localProxyMu sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	connected    bool
}

// TunnelHandler handles a single tunnel
type TunnelHandler struct {
	ID         uint32
	Protocol   string
	TargetHost string
	TargetPort uint16
	handler    TunnelProcessor
}

// TunnelProcessor is the interface for tunnel data processing
type TunnelProcessor interface {
	Start() error
	Stop()
	HandleData(data []byte) error
}

// NewClient creates a new agent client
func NewClient(cfg *Config) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:       cfg,
		agentID:      utils.GenerateID(16),
		tunnels:      make(map[uint32]*TunnelHandler),
		localProxies: make(map[string]*P2PProxy),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Run starts the agent client
func (c *Client) Run() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			log.Printf("Connection failed: %v, retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		}

		c.connected = true
		log.Printf("Connected to server")

		// Start heartbeat
		go c.heartbeat()

		// Handle messages
		c.handleMessages()

		c.connected = false
		log.Printf("Disconnected from server, reconnecting...")

		// Cleanup tunnels and local proxies
		c.cleanupTunnels()
		c.cleanupLocalProxies()

		time.Sleep(2 * time.Second)
	}
}

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() {
	c.cancel()

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connMu.Unlock()

	c.cleanupTunnels()
	c.cleanupLocalProxies()
}

func (c *Client) connect() error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(c.config.ServerURL, nil)
	if err != nil {
		return err
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	// Send authentication
	authMsg := protocol.NewAuthMessage(c.config.Token, c.config.Name, c.agentID)
	if err := c.sendMessage(authMsg); err != nil {
		conn.Close()
		return err
	}

	// Wait for auth response
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return err
	}
	conn.SetReadDeadline(time.Time{})

	msg, err := protocol.DecodeFromBytes(data)
	if err != nil {
		conn.Close()
		return err
	}

	if msg.Type != protocol.MsgTypeAuthResponse {
		conn.Close()
		return err
	}

	authResp, err := protocol.DecodeAuthResponsePayload(msg.Payload)
	if err != nil {
		conn.Close()
		return err
	}

	if !authResp.Success {
		conn.Close()
		return err
	}

	if authResp.AgentID != "" {
		c.agentID = authResp.AgentID
	}

	log.Printf("Authenticated as agent %s", c.agentID)

	return nil
}

func (c *Client) handleMessages() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.connMu.Lock()
		conn := c.conn
		c.connMu.Unlock()

		if conn == nil {
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Read error: %v", err)
			}
			return
		}

		msg, err := protocol.DecodeFromBytes(data)
		if err != nil {
			log.Printf("Failed to decode message: %v", err)
			continue
		}

		switch msg.Type {
		case protocol.MsgTypeHeartbeatAck:
			// Heartbeat acknowledged

		case protocol.MsgTypeConnect:
			go c.handleConnect(msg)

		case protocol.MsgTypeData:
			c.handleData(msg)

		case protocol.MsgTypeUDPData:
			c.handleUDPData(msg)

		case protocol.MsgTypeICMPData:
			c.handleICMPData(msg)

		case protocol.MsgTypeClose:
			c.handleClose(msg)

		case protocol.MsgTypeLocalProxyStart:
			go c.handleLocalProxyStart(msg)

		case protocol.MsgTypeLocalProxyStop:
			c.handleLocalProxyStop(msg)

		case protocol.MsgTypeP2PConnectAck:
			c.handleP2PConnectAck(msg)

		case protocol.MsgTypeP2PData:
			c.handleP2PData(msg)
		}
	}
}

func (c *Client) handleConnect(msg *protocol.Message) {
	payload, err := protocol.DecodeConnectPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode connect payload: %v", err)
		c.sendConnectAck(msg.TunnelID, false, "Invalid payload")
		return
	}

	log.Printf("Tunnel connect request: tunnelID=%d, protocol=%s, target=%s:%d",
		msg.TunnelID, payload.Protocol, payload.TargetHost, payload.TargetPort)

	var processor TunnelProcessor
	switch payload.Protocol {
	case "tcp":
		processor = NewTCPTunnel(c, msg.TunnelID, payload.TargetHost, payload.TargetPort)
	case "udp":
		processor = NewUDPTunnel(c, msg.TunnelID, payload.TargetHost, payload.TargetPort)
	case "icmp":
		processor = NewICMPTunnel(c, msg.TunnelID, payload.TargetHost)
	default:
		c.sendConnectAck(msg.TunnelID, false, "Unknown protocol")
		return
	}

	log.Printf("Tunnel %d: connecting to %s:%d...", msg.TunnelID, payload.TargetHost, payload.TargetPort)

	if err := processor.Start(); err != nil {
		log.Printf("Tunnel %d: failed to connect to %s:%d: %v", msg.TunnelID, payload.TargetHost, payload.TargetPort, err)
		c.sendConnectAck(msg.TunnelID, false, err.Error())
		return
	}

	handler := &TunnelHandler{
		ID:         msg.TunnelID,
		Protocol:   payload.Protocol,
		TargetHost: payload.TargetHost,
		TargetPort: payload.TargetPort,
		handler:    processor,
	}

	c.tunnelsMu.Lock()
	c.tunnels[msg.TunnelID] = handler
	c.tunnelsMu.Unlock()

	log.Printf("Tunnel %d: connected successfully, sending ack", msg.TunnelID)
	c.sendConnectAck(msg.TunnelID, true, "")
	log.Printf("Tunnel %d established: %s -> %s:%d", msg.TunnelID, payload.Protocol, payload.TargetHost, payload.TargetPort)
}

func (c *Client) handleData(msg *protocol.Message) {
	c.tunnelsMu.RLock()
	handler, exists := c.tunnels[msg.TunnelID]
	c.tunnelsMu.RUnlock()

	if !exists {
		return
	}

	if err := handler.handler.HandleData(msg.Payload); err != nil {
		log.Printf("Failed to handle data for tunnel %d: %v", msg.TunnelID, err)
		c.closeTunnel(msg.TunnelID)
	}
}

func (c *Client) handleUDPData(msg *protocol.Message) {
	payload, err := protocol.DecodeUDPDataPayload(msg.Payload)
	if err != nil {
		return
	}

	c.tunnelsMu.RLock()
	handler, exists := c.tunnels[msg.TunnelID]
	c.tunnelsMu.RUnlock()

	if !exists || handler.Protocol != "udp" {
		return
	}

	if udpTunnel, ok := handler.handler.(*UDPTunnel); ok {
		udpTunnel.HandleUDPData(payload)
	}
}

func (c *Client) handleICMPData(msg *protocol.Message) {
	payload, err := protocol.DecodeICMPDataPayload(msg.Payload)
	if err != nil {
		return
	}

	c.tunnelsMu.RLock()
	handler, exists := c.tunnels[msg.TunnelID]
	c.tunnelsMu.RUnlock()

	if !exists || handler.Protocol != "icmp" {
		return
	}

	if icmpTunnel, ok := handler.handler.(*ICMPTunnel); ok {
		icmpTunnel.HandleICMPData(payload)
	}
}

func (c *Client) handleClose(msg *protocol.Message) {
	c.closeTunnel(msg.TunnelID)
}

func (c *Client) closeTunnel(tunnelID uint32) {
	c.tunnelsMu.Lock()
	handler, exists := c.tunnels[tunnelID]
	if exists {
		handler.handler.Stop()
		delete(c.tunnels, tunnelID)
	}
	c.tunnelsMu.Unlock()

	if exists {
		log.Printf("Tunnel %d closed", tunnelID)
	}
}

func (c *Client) cleanupTunnels() {
	c.tunnelsMu.Lock()
	for id, handler := range c.tunnels {
		handler.handler.Stop()
		delete(c.tunnels, id)
	}
	c.tunnelsMu.Unlock()
}

func (c *Client) sendConnectAck(tunnelID uint32, success bool, errMsg string) {
	payload := protocol.EncodeConnectAckPayload(&protocol.ConnectAckPayload{
		Success:  success,
		TunnelID: tunnelID,
		Error:    errMsg,
	})
	msg := protocol.NewMessage(protocol.MsgTypeConnectAck, tunnelID, payload)
	c.sendMessage(msg)
}

func (c *Client) sendMessage(msg *protocol.Message) error {
	data, err := msg.Encode()
	if err != nil {
		return err
	}

	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn == nil {
		return nil
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendData sends data to the cloud server
func (c *Client) SendData(tunnelID uint32, data []byte) error {
	msg := protocol.NewDataMessage(tunnelID, data)
	return c.sendMessage(msg)
}

// SendClose sends a close message
func (c *Client) SendClose(tunnelID uint32) error {
	msg := protocol.NewCloseMessage(tunnelID)
	return c.sendMessage(msg)
}

func (c *Client) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if !c.connected {
				return
			}
			c.sendMessage(protocol.NewHeartbeatMessage())
		}
	}
}

func (c *Client) handleLocalProxyStart(msg *protocol.Message) {
	payload, err := protocol.DecodeLocalProxyStartPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode local proxy start payload: %v", err)
		return
	}

	log.Printf("Starting local proxy: %s on port %d -> %s:%s:%d",
		payload.RuleID, payload.ListenPort, payload.TargetAgentID, payload.TargetHost, payload.TargetPort)

	c.localProxyMu.Lock()
	if _, exists := c.localProxies[payload.RuleID]; exists {
		c.localProxyMu.Unlock()
		log.Printf("Local proxy %s already exists", payload.RuleID)
		return
	}
	c.localProxyMu.Unlock()

	proxy := NewP2PProxy(c, payload.RuleID, int(payload.ListenPort), payload.TargetAgentID, payload.TargetHost, int(payload.TargetPort), payload.Protocol)
	if err := proxy.Start(); err != nil {
		log.Printf("Failed to start local proxy %s: %v", payload.RuleID, err)
		return
	}

	c.localProxyMu.Lock()
	c.localProxies[payload.RuleID] = proxy
	c.localProxyMu.Unlock()

	log.Printf("Local proxy %s started on port %d", payload.RuleID, payload.ListenPort)
}

func (c *Client) handleLocalProxyStop(msg *protocol.Message) {
	payload, err := protocol.DecodeLocalProxyStopPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode local proxy stop payload: %v", err)
		return
	}

	c.localProxyMu.Lock()
	proxy, exists := c.localProxies[payload.RuleID]
	if exists {
		proxy.Stop()
		delete(c.localProxies, payload.RuleID)
	}
	c.localProxyMu.Unlock()

	if exists {
		log.Printf("Local proxy %s stopped", payload.RuleID)
	}
}

func (c *Client) handleP2PConnectAck(msg *protocol.Message) {
	ack, err := protocol.DecodeConnectAckPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode P2P connect ack: %v", err)
		return
	}

	// Find the proxy that has this pending tunnel
	c.localProxyMu.RLock()
	for _, proxy := range c.localProxies {
		proxy.HandleConnectAck(msg.TunnelID, ack)
	}
	c.localProxyMu.RUnlock()
}

func (c *Client) handleP2PData(msg *protocol.Message) {
	// Find the proxy connection for this tunnel
	c.localProxyMu.RLock()
	for _, proxy := range c.localProxies {
		if proxy.HandleData(msg.TunnelID, msg.Payload) {
			c.localProxyMu.RUnlock()
			return
		}
	}
	c.localProxyMu.RUnlock()
}

func (c *Client) cleanupLocalProxies() {
	c.localProxyMu.Lock()
	for id, proxy := range c.localProxies {
		proxy.Stop()
		delete(c.localProxies, id)
	}
	c.localProxyMu.Unlock()
}

