package agent

import (
	"context"
	"fmt"
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
	config            *Config
	agentID           string
	conn              *websocket.Conn // Main control connection
	connMu            sync.Mutex
	tunnels           map[uint32]*TunnelHandler
	tunnelsMu         sync.RWMutex
	localProxies      map[string]*P2PProxy        // rule ID -> P2P proxy
	localProxyMu      sync.RWMutex
	agentCloudProxies map[string]*AgentCloudProxy // rule ID -> agent-cloud proxy
	agentCloudProxyMu sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	connected         bool
	// Rule-specific connections (per-rule isolation)
	ruleConns   map[string]*RuleConnection // ruleID -> connection
	ruleConnsMu sync.RWMutex
}

// RuleConnection represents a rule-specific WebSocket connection
type RuleConnection struct {
	RuleID    string
	Conn      *websocket.Conn
	connMu    sync.Mutex
	tunnels   map[uint32]*TunnelHandler // Tunnels on this rule connection
	tunnelsMu sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	connected bool
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
		config:            cfg,
		agentID:           utils.GenerateID(16),
		tunnels:           make(map[uint32]*TunnelHandler),
		localProxies:      make(map[string]*P2PProxy),
		agentCloudProxies: make(map[string]*AgentCloudProxy),
		ruleConns:         make(map[string]*RuleConnection),
		ctx:               ctx,
		cancel:            cancel,
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

		// Cleanup tunnels and proxies
		c.cleanupTunnels()
		c.cleanupLocalProxies()
		c.cleanupAgentCloudProxies()

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
	c.cleanupAgentCloudProxies()
	c.cleanupRuleConnections()
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

		case protocol.MsgTypeAgentCloudProxyStart:
			go c.handleAgentCloudProxyStart(msg)

		case protocol.MsgTypeAgentCloudProxyStop:
			c.handleAgentCloudProxyStop(msg)

		case protocol.MsgTypeAgentCloudConnectAck:
			c.handleAgentCloudConnectAck(msg)

		case protocol.MsgTypeAgentCloudData:
			c.handleAgentCloudData(msg)
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

// ConnectRuleConnection establishes a dedicated connection for a rule
func (c *Client) ConnectRuleConnection(ruleID string) (*RuleConnection, error) {
	c.ruleConnsMu.Lock()
	// Check if already connected
	if existing, ok := c.ruleConns[ruleID]; ok && existing.connected {
		c.ruleConnsMu.Unlock()
		return existing, nil
	}
	c.ruleConnsMu.Unlock()

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(c.config.ServerURL, nil)
	if err != nil {
		return nil, err
	}

	// Send rule auth
	payload := protocol.EncodeRuleAuthPayload(&protocol.RuleAuthPayload{
		Token:   c.config.Token,
		AgentID: c.agentID,
		RuleID:  ruleID,
	})
	authMsg := protocol.NewMessage(protocol.MsgTypeRuleAuth, 0, payload)
	data, err := authMsg.Encode()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		conn.Close()
		return nil, err
	}

	// Wait for auth response
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, respData, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})

	msg, err := protocol.DecodeFromBytes(respData)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if msg.Type != protocol.MsgTypeRuleAuthResponse {
		conn.Close()
		return nil, fmt.Errorf("expected RuleAuthResponse, got %v", msg.Type)
	}

	authResp, err := protocol.DecodeRuleAuthResponsePayload(msg.Payload)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !authResp.Success {
		conn.Close()
		return nil, fmt.Errorf("rule auth failed: %s", authResp.Error)
	}

	ctx, cancel := context.WithCancel(c.ctx)
	ruleConn := &RuleConnection{
		RuleID:    ruleID,
		Conn:      conn,
		tunnels:   make(map[uint32]*TunnelHandler),
		ctx:       ctx,
		cancel:    cancel,
		connected: true,
	}

	c.ruleConnsMu.Lock()
	// Close existing if any
	if existing, ok := c.ruleConns[ruleID]; ok {
		existing.Close()
	}
	c.ruleConns[ruleID] = ruleConn
	c.ruleConnsMu.Unlock()

	log.Printf("Rule connection established: %s", ruleID)

	// Start message handler for this rule connection
	go c.handleRuleMessages(ruleConn)

	return ruleConn, nil
}

// handleRuleMessages handles messages on a rule-specific connection
func (c *Client) handleRuleMessages(rc *RuleConnection) {
	defer func() {
		rc.connected = false
		rc.Conn.Close()
		c.ruleConnsMu.Lock()
		delete(c.ruleConns, rc.RuleID)
		c.ruleConnsMu.Unlock()
		log.Printf("Rule connection closed: %s", rc.RuleID)
	}()

	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-c.ctx.Done():
			return
		default:
		}

		rc.connMu.Lock()
		conn := rc.Conn
		rc.connMu.Unlock()

		if conn == nil {
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Rule %s read error: %v", rc.RuleID, err)
			}
			return
		}

		msg, err := protocol.DecodeFromBytes(data)
		if err != nil {
			log.Printf("Failed to decode message on rule %s: %v", rc.RuleID, err)
			continue
		}

		switch msg.Type {
		case protocol.MsgTypeHeartbeatAck:
			// Heartbeat acknowledged

		case protocol.MsgTypeConnect:
			go c.handleRuleConnect(rc, msg)

		case protocol.MsgTypeData:
			c.handleRuleData(rc, msg)

		case protocol.MsgTypeUDPData:
			c.handleRuleUDPData(rc, msg)

		case protocol.MsgTypeClose:
			c.handleRuleClose(rc, msg)
		}
	}
}

// handleRuleConnect handles connect request on rule connection
func (c *Client) handleRuleConnect(rc *RuleConnection, msg *protocol.Message) {
	payload, err := protocol.DecodeConnectPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode connect payload on rule %s: %v", rc.RuleID, err)
		c.sendRuleConnectAck(rc, msg.TunnelID, false, "Invalid payload")
		return
	}

	log.Printf("Rule %s tunnel connect: tunnelID=%d, protocol=%s, target=%s:%d",
		rc.RuleID, msg.TunnelID, payload.Protocol, payload.TargetHost, payload.TargetPort)

	var processor TunnelProcessor
	switch payload.Protocol {
	case "tcp":
		processor = NewRuleTCPTunnel(c, rc, msg.TunnelID, payload.TargetHost, payload.TargetPort)
	case "udp":
		processor = NewRuleUDPTunnel(c, rc, msg.TunnelID, payload.TargetHost, payload.TargetPort)
	default:
		c.sendRuleConnectAck(rc, msg.TunnelID, false, "Unknown protocol")
		return
	}

	if err := processor.Start(); err != nil {
		log.Printf("Rule %s tunnel %d: failed to connect: %v", rc.RuleID, msg.TunnelID, err)
		c.sendRuleConnectAck(rc, msg.TunnelID, false, err.Error())
		return
	}

	handler := &TunnelHandler{
		ID:         msg.TunnelID,
		Protocol:   payload.Protocol,
		TargetHost: payload.TargetHost,
		TargetPort: payload.TargetPort,
		handler:    processor,
	}

	rc.tunnelsMu.Lock()
	rc.tunnels[msg.TunnelID] = handler
	rc.tunnelsMu.Unlock()

	c.sendRuleConnectAck(rc, msg.TunnelID, true, "")
	log.Printf("Rule %s tunnel %d established: %s -> %s:%d",
		rc.RuleID, msg.TunnelID, payload.Protocol, payload.TargetHost, payload.TargetPort)
}

func (c *Client) handleRuleData(rc *RuleConnection, msg *protocol.Message) {
	rc.tunnelsMu.RLock()
	handler, exists := rc.tunnels[msg.TunnelID]
	rc.tunnelsMu.RUnlock()

	if !exists {
		return
	}

	if err := handler.handler.HandleData(msg.Payload); err != nil {
		log.Printf("Rule %s tunnel %d: handle data error: %v", rc.RuleID, msg.TunnelID, err)
		c.closeRuleTunnel(rc, msg.TunnelID)
	}
}

func (c *Client) handleRuleUDPData(rc *RuleConnection, msg *protocol.Message) {
	payload, err := protocol.DecodeUDPDataPayload(msg.Payload)
	if err != nil {
		return
	}

	rc.tunnelsMu.RLock()
	handler, exists := rc.tunnels[msg.TunnelID]
	rc.tunnelsMu.RUnlock()

	if !exists || handler.Protocol != "udp" {
		return
	}

	if udpTunnel, ok := handler.handler.(*RuleUDPTunnel); ok {
		udpTunnel.HandleUDPData(payload)
	}
}

func (c *Client) handleRuleClose(rc *RuleConnection, msg *protocol.Message) {
	c.closeRuleTunnel(rc, msg.TunnelID)
}

func (c *Client) closeRuleTunnel(rc *RuleConnection, tunnelID uint32) {
	rc.tunnelsMu.Lock()
	handler, exists := rc.tunnels[tunnelID]
	if exists {
		handler.handler.Stop()
		delete(rc.tunnels, tunnelID)
	}
	rc.tunnelsMu.Unlock()

	if exists {
		log.Printf("Rule %s tunnel %d closed", rc.RuleID, tunnelID)
	}
}

func (c *Client) sendRuleConnectAck(rc *RuleConnection, tunnelID uint32, success bool, errMsg string) {
	payload := protocol.EncodeConnectAckPayload(&protocol.ConnectAckPayload{
		Success:  success,
		TunnelID: tunnelID,
		Error:    errMsg,
	})
	msg := protocol.NewMessage(protocol.MsgTypeConnectAck, tunnelID, payload)
	c.sendRuleMessage(rc, msg)
}

func (c *Client) sendRuleMessage(rc *RuleConnection, msg *protocol.Message) error {
	data, err := msg.Encode()
	if err != nil {
		return err
	}

	rc.connMu.Lock()
	defer rc.connMu.Unlock()

	if rc.Conn == nil {
		return fmt.Errorf("rule connection is nil")
	}

	return rc.Conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendRuleData sends data on a rule connection
func (c *Client) SendRuleData(rc *RuleConnection, tunnelID uint32, data []byte) error {
	msg := protocol.NewDataMessage(tunnelID, data)
	return c.sendRuleMessage(rc, msg)
}

// SendRuleClose sends close message on a rule connection
func (c *Client) SendRuleClose(rc *RuleConnection, tunnelID uint32) error {
	msg := protocol.NewCloseMessage(tunnelID)
	return c.sendRuleMessage(rc, msg)
}

// Close closes a rule connection
func (rc *RuleConnection) Close() {
	rc.cancel()
	rc.connMu.Lock()
	if rc.Conn != nil {
		rc.Conn.Close()
	}
	rc.connMu.Unlock()

	// Close all tunnels
	rc.tunnelsMu.Lock()
	for id, handler := range rc.tunnels {
		handler.handler.Stop()
		delete(rc.tunnels, id)
	}
	rc.tunnelsMu.Unlock()
}

// GetRuleConnection gets or creates a rule connection
func (c *Client) GetRuleConnection(ruleID string) *RuleConnection {
	c.ruleConnsMu.RLock()
	rc, exists := c.ruleConns[ruleID]
	c.ruleConnsMu.RUnlock()

	if exists && rc.connected {
		return rc
	}
	return nil
}

// cleanupRuleConnections cleans up all rule connections
func (c *Client) cleanupRuleConnections() {
	c.ruleConnsMu.Lock()
	for id, rc := range c.ruleConns {
		rc.Close()
		delete(c.ruleConns, id)
	}
	c.ruleConnsMu.Unlock()
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

	// Establish dedicated rule connection
	ruleConn, err := c.ConnectRuleConnection(payload.RuleID)
	if err != nil {
		log.Printf("Failed to establish rule connection for %s: %v", payload.RuleID, err)
		// Continue anyway, will use main connection as fallback
	} else {
		log.Printf("Rule connection established for %s", payload.RuleID)
		_ = ruleConn // ruleConn is stored in c.ruleConns and used by proxy
	}

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

	// Close rule connection
	c.ruleConnsMu.Lock()
	if rc, ok := c.ruleConns[payload.RuleID]; ok {
		rc.Close()
		delete(c.ruleConns, payload.RuleID)
	}
	c.ruleConnsMu.Unlock()

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

func (c *Client) handleAgentCloudProxyStart(msg *protocol.Message) {
	payload, err := protocol.DecodeAgentCloudProxyStartPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode agent-cloud proxy start payload: %v", err)
		return
	}

	log.Printf("Starting agent-cloud proxy: %s on port %d -> cloud -> %s:%d",
		payload.RuleID, payload.ListenPort, payload.TargetHost, payload.TargetPort)

	c.agentCloudProxyMu.Lock()
	if _, exists := c.agentCloudProxies[payload.RuleID]; exists {
		c.agentCloudProxyMu.Unlock()
		log.Printf("Agent-cloud proxy %s already exists", payload.RuleID)
		return
	}
	c.agentCloudProxyMu.Unlock()

	// Establish dedicated rule connection
	ruleConn, err := c.ConnectRuleConnection(payload.RuleID)
	if err != nil {
		log.Printf("Failed to establish rule connection for %s: %v", payload.RuleID, err)
		// Continue anyway, will use main connection as fallback
	} else {
		log.Printf("Rule connection established for %s", payload.RuleID)
		_ = ruleConn // ruleConn is stored in c.ruleConns and used by proxy
	}

	proxy := NewAgentCloudProxy(c, payload.RuleID, int(payload.ListenPort), payload.TargetHost, int(payload.TargetPort), payload.Protocol)
	if err := proxy.Start(); err != nil {
		log.Printf("Failed to start agent-cloud proxy %s: %v", payload.RuleID, err)
		return
	}

	c.agentCloudProxyMu.Lock()
	c.agentCloudProxies[payload.RuleID] = proxy
	c.agentCloudProxyMu.Unlock()

	log.Printf("Agent-cloud proxy %s started on port %d", payload.RuleID, payload.ListenPort)
}

func (c *Client) handleAgentCloudProxyStop(msg *protocol.Message) {
	payload, err := protocol.DecodeAgentCloudProxyStopPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode agent-cloud proxy stop payload: %v", err)
		return
	}

	c.agentCloudProxyMu.Lock()
	proxy, exists := c.agentCloudProxies[payload.RuleID]
	if exists {
		proxy.Stop()
		delete(c.agentCloudProxies, payload.RuleID)
	}
	c.agentCloudProxyMu.Unlock()

	// Close rule connection
	c.ruleConnsMu.Lock()
	if rc, ok := c.ruleConns[payload.RuleID]; ok {
		rc.Close()
		delete(c.ruleConns, payload.RuleID)
	}
	c.ruleConnsMu.Unlock()

	if exists {
		log.Printf("Agent-cloud proxy %s stopped", payload.RuleID)
	}
}

func (c *Client) handleAgentCloudConnectAck(msg *protocol.Message) {
	ack, err := protocol.DecodeConnectAckPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode agent-cloud connect ack: %v", err)
		return
	}

	// Find the proxy that has this pending tunnel
	c.agentCloudProxyMu.RLock()
	for _, proxy := range c.agentCloudProxies {
		proxy.HandleConnectAck(msg.TunnelID, ack)
	}
	c.agentCloudProxyMu.RUnlock()
}

func (c *Client) handleAgentCloudData(msg *protocol.Message) {
	// Find the proxy connection for this tunnel
	c.agentCloudProxyMu.RLock()
	for _, proxy := range c.agentCloudProxies {
		if proxy.HandleData(msg.TunnelID, msg.Payload) {
			c.agentCloudProxyMu.RUnlock()
			return
		}
	}
	c.agentCloudProxyMu.RUnlock()
}

func (c *Client) cleanupAgentCloudProxies() {
	c.agentCloudProxyMu.Lock()
	for id, proxy := range c.agentCloudProxies {
		proxy.Stop()
		delete(c.agentCloudProxies, id)
	}
	c.agentCloudProxyMu.Unlock()
}

