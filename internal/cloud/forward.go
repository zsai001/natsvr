package cloud

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/natsvr/natsvr/internal/protocol"
)

// Forwarder manages port forwarding rules
type Forwarder struct {
	server       *Server
	rules        map[string]*ForwardRuleState
	rulesMu      sync.RWMutex
	tunnelIDGen  uint32
	tunnelConns  map[uint32]*TunnelConn
	tunnelConnMu sync.RWMutex
	pendingAcks  map[uint32]chan *protocol.ConnectAckPayload
	pendingMu    sync.Mutex
	globalStats  *GlobalStats
}

// ForwardRuleState holds the runtime state of a forwarding rule
type ForwardRuleState struct {
	Rule        *ForwardRule
	Listener    net.Listener
	UDPConn     *net.UDPConn
	Active      bool
	RateLimiter *RateLimiter
	TrafficUsed int64 // atomic
}

// TunnelConn represents an active tunnel connection
type TunnelConn struct {
	ID            uint32
	AgentID       string
	Conn          net.Conn
	Protocol      string
	Target        string
	SourceAgentID string // For P2P tunnels, the source agent ID
	LocalTunnelID uint32 // For P2P tunnels, the source agent's local tunnel ID
}

// NewForwarder creates a new forwarder
func NewForwarder(server *Server) *Forwarder {
	return &Forwarder{
		server:      server,
		rules:       make(map[string]*ForwardRuleState),
		tunnelConns: make(map[uint32]*TunnelConn),
		pendingAcks: make(map[uint32]chan *protocol.ConnectAckPayload),
		globalStats: NewGlobalStats(),
	}
}

// GetGlobalStats returns the global traffic statistics
func (f *Forwarder) GetGlobalStats() (txBytes, rxBytes int64, txSpeed, rxSpeed float64) {
	return f.globalStats.GetStats()
}

// GetRuleTraffic returns traffic used for a specific rule
func (f *Forwarder) GetRuleTraffic(ruleID string) int64 {
	f.rulesMu.RLock()
	defer f.rulesMu.RUnlock()
	if state, ok := f.rules[ruleID]; ok {
		return atomic.LoadInt64(&state.TrafficUsed)
	}
	return 0
}

// Run starts the forwarder
func (f *Forwarder) Run() {
	// Load existing rules from store
	rules, err := f.server.store.GetForwardRules()
	if err != nil {
		log.Printf("Failed to load forward rules: %v", err)
		return
	}

	for _, rule := range rules {
		if rule.Enabled {
			f.StartRule(rule)
		}
	}
}

// StartRule starts a forwarding rule
func (f *Forwarder) StartRule(rule *ForwardRule) error {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()

	if _, exists := f.rules[rule.ID]; exists {
		return fmt.Errorf("rule %s already running", rule.ID)
	}

	state := &ForwardRuleState{
		Rule:        rule,
		Active:      true,
		RateLimiter: NewRateLimiter(rule.RateLimit),
		TrafficUsed: rule.TrafficUsed,
	}

	switch rule.Type {
	case "remote":
		// Cloud listens, forwards to agent
		if rule.Protocol == "tcp" {
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rule.ListenPort))
			if err != nil {
				return fmt.Errorf("failed to listen on port %d: %v", rule.ListenPort, err)
			}
			state.Listener = listener
			go f.handleRemoteTCPListener(state)
		} else if rule.Protocol == "udp" {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", rule.ListenPort))
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return fmt.Errorf("failed to listen on UDP port %d: %v", rule.ListenPort, err)
			}
			state.UDPConn = conn
			go f.handleRemoteUDPListener(state)
		}
	case "cloud-self":
		// Cloud listens, forwards directly to target server (no agent involved)
		if rule.Protocol == "tcp" {
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rule.ListenPort))
			if err != nil {
				return fmt.Errorf("failed to listen on port %d: %v", rule.ListenPort, err)
			}
			state.Listener = listener
			go f.handleCloudSelfTCPListener(state)
		} else if rule.Protocol == "udp" {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", rule.ListenPort))
			if err != nil {
				return err
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return fmt.Errorf("failed to listen on UDP port %d: %v", rule.ListenPort, err)
			}
			state.UDPConn = conn
			go f.handleCloudSelfUDPListener(state)
		}
	case "local", "p2p":
		// Agent to agent forwarding - notify source agent to start listening
		if rule.SourceAgentID != "" {
			// Try to find source agent by name first, then by ID
			sourceAgent := f.server.GetAgentByName(rule.SourceAgentID)
			if sourceAgent == nil {
				sourceAgent = f.server.GetAgent(rule.SourceAgentID)
			}
			if sourceAgent != nil {
				log.Printf("Sending local proxy rule %s to source agent %s", rule.Name, sourceAgent.Name)
				f.sendLocalProxyStart(sourceAgent, rule)
			} else {
				log.Printf("Source agent %s not connected, rule will be sent when agent connects", rule.SourceAgentID)
			}
		}
	}

	f.rules[rule.ID] = state
	log.Printf("Started forward rule: %s (%s:%d -> %s:%s:%d)",
		rule.Name, rule.Protocol, rule.ListenPort,
		rule.TargetAgentID, rule.TargetHost, rule.TargetPort)

	return nil
}

// StopRule stops a forwarding rule
func (f *Forwarder) StopRule(ruleID string) error {
	f.rulesMu.Lock()
	state, exists := f.rules[ruleID]
	if !exists {
		f.rulesMu.Unlock()
		return nil
	}

	state.Active = false
	if state.Listener != nil {
		state.Listener.Close()
	}
	if state.UDPConn != nil {
		state.UDPConn.Close()
	}

	// Save traffic used to database
	trafficUsed := atomic.LoadInt64(&state.TrafficUsed)
	f.server.store.UpdateTrafficUsed(ruleID, trafficUsed)

	rule := state.Rule
	delete(f.rules, ruleID)
	f.rulesMu.Unlock()

	// For local/p2p rules, notify source agent to stop
	if (rule.Type == "local" || rule.Type == "p2p") && rule.SourceAgentID != "" {
		sourceAgent := f.server.GetAgentByName(rule.SourceAgentID)
		if sourceAgent == nil {
			sourceAgent = f.server.GetAgent(rule.SourceAgentID)
		}
		if sourceAgent != nil {
			f.sendLocalProxyStop(sourceAgent, ruleID)
		}
	}

	log.Printf("Stopped forward rule: %s", rule.Name)

	return nil
}

// addTraffic adds traffic to rule state and checks limits
// Returns false if traffic limit exceeded
func (f *Forwarder) addTraffic(state *ForwardRuleState, n int64) bool {
	newTotal := atomic.AddInt64(&state.TrafficUsed, n)
	f.globalStats.AddTx(n)
	
	// Check traffic limit
	if state.Rule.TrafficLimit > 0 && newTotal > state.Rule.TrafficLimit {
		return false
	}
	return true
}

func (f *Forwarder) handleRemoteTCPListener(state *ForwardRuleState) {
	for state.Active {
		conn, err := state.Listener.Accept()
		if err != nil {
			if state.Active {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		go f.handleRemoteTCPConnection(state, conn)
	}
}

func (f *Forwarder) handleRemoteTCPConnection(state *ForwardRuleState, conn net.Conn) {
	defer conn.Close()

	// Check traffic limit before starting
	if state.Rule.TrafficLimit > 0 && atomic.LoadInt64(&state.TrafficUsed) >= state.Rule.TrafficLimit {
		log.Printf("Traffic limit exceeded for rule %s", state.Rule.Name)
		return
	}

	rule := state.Rule
	agent := f.server.GetAgent(rule.TargetAgentID)
	if agent == nil {
		log.Printf("Target agent %s not connected", rule.TargetAgentID)
		return
	}

	// Generate tunnel ID
	tunnelID := atomic.AddUint32(&f.tunnelIDGen, 1)

	// Create pending ack channel
	ackChan := make(chan *protocol.ConnectAckPayload, 1)
	f.pendingMu.Lock()
	f.pendingAcks[tunnelID] = ackChan
	f.pendingMu.Unlock()

	defer func() {
		f.pendingMu.Lock()
		delete(f.pendingAcks, tunnelID)
		f.pendingMu.Unlock()
	}()

	// Send connect request to agent
	connectMsg := protocol.NewConnectMessage(tunnelID, "tcp", rule.TargetHost, uint16(rule.TargetPort))
	if err := f.server.sendToAgent(agent, connectMsg); err != nil {
		log.Printf("Failed to send connect message: %v", err)
		return
	}

	// Wait for acknowledgment
	select {
	case ack := <-ackChan:
		if !ack.Success {
			log.Printf("Tunnel connect failed: %s", ack.Error)
			return
		}
	case <-time.After(30 * time.Second):
		log.Printf("Tunnel connect timeout")
		return
	}

	// Register tunnel connection
	tunnelConn := &TunnelConn{
		ID:       tunnelID,
		AgentID:  agent.ID,
		Conn:     conn,
		Protocol: "tcp",
		Target:   fmt.Sprintf("%s:%d", rule.TargetHost, rule.TargetPort),
	}

	f.tunnelConnMu.Lock()
	f.tunnelConns[tunnelID] = tunnelConn
	f.tunnelConnMu.Unlock()

	agent.tunnelsMu.Lock()
	agent.tunnels[tunnelID] = &Tunnel{
		ID:         tunnelID,
		Protocol:   "tcp",
		TargetHost: rule.TargetHost,
		TargetPort: uint16(rule.TargetPort),
		CreatedAt:  time.Now(),
	}
	agent.ActiveTunnels++
	agent.tunnelsMu.Unlock()

	defer func() {
		f.tunnelConnMu.Lock()
		delete(f.tunnelConns, tunnelID)
		f.tunnelConnMu.Unlock()

		agent.tunnelsMu.Lock()
		delete(agent.tunnels, tunnelID)
		agent.ActiveTunnels--
		agent.tunnelsMu.Unlock()

		// Send close message
		f.server.sendToAgent(agent, protocol.NewCloseMessage(tunnelID))
	}()

	// Forward data from client to agent
	buf := make([]byte, 32768)
	for state.Active {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			// Check traffic limit
			if !f.addTraffic(state, int64(n)) {
				log.Printf("Traffic limit exceeded for rule %s", state.Rule.Name)
				return
			}

			// Apply rate limit
			if state.RateLimiter != nil {
				state.RateLimiter.Wait(int64(n))
			}

			dataMsg := protocol.NewDataMessage(tunnelID, buf[:n])
			if err := f.server.sendToAgent(agent, dataMsg); err != nil {
				return
			}
		}
	}
}

func (f *Forwarder) handleRemoteUDPListener(state *ForwardRuleState) {
	rule := state.Rule
	buf := make([]byte, 65535)
	clients := make(map[string]time.Time)

	for state.Active {
		state.UDPConn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := state.UDPConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		agent := f.server.GetAgent(rule.TargetAgentID)
		if agent == nil {
			continue
		}

		clients[addr.String()] = time.Now()

		// Send UDP data to agent
		payload := protocol.EncodeUDPDataPayload(&protocol.UDPDataPayload{
			SourceAddr: addr.IP.String(),
			SourcePort: uint16(addr.Port),
			DestAddr:   rule.TargetHost,
			DestPort:   uint16(rule.TargetPort),
			Data:       buf[:n],
		})

		msg := protocol.NewMessage(protocol.MsgTypeUDPData, 0, payload)
		f.server.sendToAgent(agent, msg)
	}
}

// handleCloudSelfTCPListener handles TCP connections for cloud-self forwarding
func (f *Forwarder) handleCloudSelfTCPListener(state *ForwardRuleState) {
	for state.Active {
		conn, err := state.Listener.Accept()
		if err != nil {
			if state.Active {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		go f.handleCloudSelfTCPConnection(state, conn)
	}
}

// handleCloudSelfTCPConnection handles a single TCP connection for cloud-self forwarding
func (f *Forwarder) handleCloudSelfTCPConnection(state *ForwardRuleState, clientConn net.Conn) {
	defer clientConn.Close()

	// Check traffic limit before starting
	if state.Rule.TrafficLimit > 0 && atomic.LoadInt64(&state.TrafficUsed) >= state.Rule.TrafficLimit {
		log.Printf("Traffic limit exceeded for rule %s", state.Rule.Name)
		return
	}

	rule := state.Rule
	targetAddr := fmt.Sprintf("%s:%d", rule.TargetHost, rule.TargetPort)

	// Connect to target server directly
	targetConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy with rate limiting and traffic tracking
	done := make(chan struct{}, 2)

	// Client -> Target
	go func() {
		f.copyWithLimits(state, targetConn, clientConn)
		done <- struct{}{}
	}()

	// Target -> Client
	go func() {
		f.copyWithLimits(state, clientConn, targetConn)
		done <- struct{}{}
	}()

	// Wait for either direction to complete
	<-done
}

// copyWithLimits copies data with rate limiting and traffic tracking
func (f *Forwarder) copyWithLimits(state *ForwardRuleState, dst io.Writer, src io.Reader) {
	buf := make([]byte, 32768)
	for state.Active {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			// Check traffic limit
			if !f.addTraffic(state, int64(n)) {
				log.Printf("Traffic limit exceeded for rule %s", state.Rule.Name)
				return
			}
			
			// Apply rate limit
			if state.RateLimiter != nil {
				state.RateLimiter.Wait(int64(n))
			}
			
			_, err = dst.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}
}

// handleCloudSelfUDPListener handles UDP packets for cloud-self forwarding
func (f *Forwarder) handleCloudSelfUDPListener(state *ForwardRuleState) {
	rule := state.Rule
	buf := make([]byte, 65535)
	targetAddr := fmt.Sprintf("%s:%d", rule.TargetHost, rule.TargetPort)

	// Map to track client connections
	clients := make(map[string]*net.UDPConn)
	clientsMu := sync.Mutex{}

	for state.Active {
		state.UDPConn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := state.UDPConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		clientKey := clientAddr.String()

		clientsMu.Lock()
		targetConn, exists := clients[clientKey]
		if !exists {
			// Create new connection to target
			raddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				clientsMu.Unlock()
				log.Printf("Failed to resolve target address %s: %v", targetAddr, err)
				continue
			}
			targetConn, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				clientsMu.Unlock()
				log.Printf("Failed to connect to target %s: %v", targetAddr, err)
				continue
			}
			clients[clientKey] = targetConn

			// Start goroutine to receive responses
			go func(clientAddr *net.UDPAddr, targetConn *net.UDPConn) {
				respBuf := make([]byte, 65535)
				for {
					targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := targetConn.Read(respBuf)
					if err != nil {
						clientsMu.Lock()
						delete(clients, clientAddr.String())
						clientsMu.Unlock()
						targetConn.Close()
						return
					}
					state.UDPConn.WriteToUDP(respBuf[:n], clientAddr)
				}
			}(clientAddr, targetConn)
		}
		clientsMu.Unlock()

		// Forward data to target
		targetConn.Write(buf[:n])
	}

	// Cleanup all connections
	clientsMu.Lock()
	for _, conn := range clients {
		conn.Close()
	}
	clientsMu.Unlock()
}

// HandleData handles incoming data from an agent
func (f *Forwarder) HandleData(agent *AgentConn, msg *protocol.Message) {
	f.tunnelConnMu.RLock()
	tunnelConn, exists := f.tunnelConns[msg.TunnelID]
	f.tunnelConnMu.RUnlock()

	if !exists {
		return
	}

	// Check if this is a P2P tunnel (no local connection, forward to source agent)
	if tunnelConn.Conn == nil {
		// This is P2P data from target agent, forward to source agent
		f.HandleP2PDataReverse(agent, msg.TunnelID, msg.Payload)
		return
	}

	_, err := tunnelConn.Conn.Write(msg.Payload)
	if err != nil {
		tunnelConn.Conn.Close()
	}
}

// HandleUDPData handles incoming UDP data from an agent
func (f *Forwarder) HandleUDPData(agent *AgentConn, msg *protocol.Message) {
	payload, err := protocol.DecodeUDPDataPayload(msg.Payload)
	if err != nil {
		return
	}

	// Find the rule that matches this response
	f.rulesMu.RLock()
	for _, state := range f.rules {
		if state.Rule.TargetAgentID == agent.ID && state.UDPConn != nil {
			addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort))
			state.UDPConn.WriteToUDP(payload.Data, addr)
			break
		}
	}
	f.rulesMu.RUnlock()
}

// HandleICMPData handles incoming ICMP data from an agent
func (f *Forwarder) HandleICMPData(agent *AgentConn, msg *protocol.Message) {
	// ICMP handling - requires raw sockets, typically needs root privileges
	log.Printf("Received ICMP data from agent %s", agent.ID)
}

// HandleConnectAck handles tunnel connect acknowledgment
func (f *Forwarder) HandleConnectAck(agent *AgentConn, msg *protocol.Message) {
	ack, err := protocol.DecodeConnectAckPayload(msg.Payload)
	if err != nil {
		log.Printf("HandleConnectAck: failed to decode payload: %v", err)
		return
	}

	log.Printf("HandleConnectAck: from agent %s, tunnelID=%d, success=%v", agent.ID, msg.TunnelID, ack.Success)

	f.pendingMu.Lock()
	ch, exists := f.pendingAcks[msg.TunnelID]
	f.pendingMu.Unlock()

	if exists {
		log.Printf("HandleConnectAck: found pending channel for tunnelID=%d, sending ack", msg.TunnelID)
		ch <- ack
	} else {
		log.Printf("HandleConnectAck: no pending channel for tunnelID=%d", msg.TunnelID)
	}
}

// HandleClose handles tunnel close message
func (f *Forwarder) HandleClose(agent *AgentConn, msg *protocol.Message) {
	f.tunnelConnMu.Lock()
	tunnelConn, exists := f.tunnelConns[msg.TunnelID]
	if exists {
		// Only close Conn if it's not nil (P2P tunnels don't have a local Conn)
		if tunnelConn.Conn != nil {
			tunnelConn.Conn.Close()
		}
		delete(f.tunnelConns, msg.TunnelID)
		log.Printf("Tunnel %d closed by agent %s", msg.TunnelID, agent.ID)
	}
	f.tunnelConnMu.Unlock()

	agent.tunnelsMu.Lock()
	if _, ok := agent.tunnels[msg.TunnelID]; ok {
		delete(agent.tunnels, msg.TunnelID)
		agent.ActiveTunnels--
	}
	agent.tunnelsMu.Unlock()
}

// SendToAgent sends a message to an agent
func (f *Forwarder) SendToAgent(agentID string, msg *protocol.Message) error {
	agent := f.server.GetAgent(agentID)
	if agent == nil {
		return fmt.Errorf("agent %s not found", agentID)
	}

	data, err := msg.Encode()
	if err != nil {
		return err
	}

	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()

	return agent.Conn.WriteMessage(websocket.BinaryMessage, data)
}

// sendLocalProxyStart sends a local proxy start message to an agent
func (f *Forwarder) sendLocalProxyStart(agent *AgentConn, rule *ForwardRule) error {
	payload := protocol.EncodeLocalProxyStartPayload(&protocol.LocalProxyStartPayload{
		RuleID:        rule.ID,
		Protocol:      rule.Protocol,
		ListenPort:    uint16(rule.ListenPort),
		TargetAgentID: rule.TargetAgentID,
		TargetHost:    rule.TargetHost,
		TargetPort:    uint16(rule.TargetPort),
	})
	msg := protocol.NewMessage(protocol.MsgTypeLocalProxyStart, 0, payload)
	return f.server.sendToAgent(agent, msg)
}

// sendLocalProxyStop sends a local proxy stop message to an agent
func (f *Forwarder) sendLocalProxyStop(agent *AgentConn, ruleID string) error {
	payload := protocol.EncodeLocalProxyStopPayload(&protocol.LocalProxyStopPayload{
		RuleID: ruleID,
	})
	msg := protocol.NewMessage(protocol.MsgTypeLocalProxyStop, 0, payload)
	return f.server.sendToAgent(agent, msg)
}

// OnAgentConnected is called when an agent connects, to send it local proxy rules
func (f *Forwarder) OnAgentConnected(agent *AgentConn) {
	rules, err := f.server.store.GetForwardRules()
	if err != nil {
		log.Printf("Failed to load forward rules for agent %s: %v", agent.ID, err)
		return
	}

	for _, rule := range rules {
		if !rule.Enabled || (rule.Type != "local" && rule.Type != "p2p") {
			continue
		}

		// Match by ID or by name
		if rule.SourceAgentID == agent.ID || rule.SourceAgentID == agent.Name {
			log.Printf("Sending local proxy rule %s to agent %s (%s)", rule.Name, agent.Name, agent.ID)
			if err := f.sendLocalProxyStart(agent, rule); err != nil {
				log.Printf("Failed to send local proxy start to agent %s: %v", agent.ID, err)
			}
		}
	}
}

// HandleP2PConnect handles P2P connection request from source agent
func (f *Forwarder) HandleP2PConnect(sourceAgent *AgentConn, msg *protocol.Message) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic in HandleP2PConnect: %v", r)
		}
	}()

	payload, err := protocol.DecodeP2PConnectPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode P2P connect payload: %v", err)
		return
	}

	localTunnelID := msg.TunnelID // Source agent's local tunnel ID

	log.Printf("P2P connect request from agent %s: target=%s, dest=%s:%d, localTunnelID=%d",
		sourceAgent.ID, payload.SourceAgentID, payload.TargetHost, payload.TargetPort, localTunnelID)

	// Find the target agent by name
	targetAgent := f.server.GetAgentByName(payload.SourceAgentID)
	if targetAgent == nil {
		// Try by ID
		targetAgent = f.server.GetAgent(payload.SourceAgentID)
	}
	if targetAgent == nil {
		log.Printf("P2P connect: target agent %s not found (not connected)", payload.SourceAgentID)
		// Send failure ack with the local tunnel ID so source can find its pending channel
		ackPayload := protocol.EncodeConnectAckPayload(&protocol.ConnectAckPayload{
			Success:  false,
			TunnelID: localTunnelID,
			Error:    "Target agent not connected",
		})
		ackMsg := protocol.NewMessage(protocol.MsgTypeP2PConnectAck, localTunnelID, ackPayload)
		f.server.sendToAgent(sourceAgent, ackMsg)
		return
	}

	log.Printf("P2P connect: found target agent %s (%s)", targetAgent.Name, targetAgent.ID)

	// Generate global tunnel ID (unique across all tunnel types)
	globalTunnelID := atomic.AddUint32(&f.tunnelIDGen, 1)

	// Create pending ack channel with global tunnel ID
	ackChan := make(chan *protocol.ConnectAckPayload, 1)
	f.pendingMu.Lock()
	f.pendingAcks[globalTunnelID] = ackChan
	log.Printf("P2P connect: created pending ack channel for globalTunnelID=%d", globalTunnelID)
	f.pendingMu.Unlock()

	defer func() {
		f.pendingMu.Lock()
		delete(f.pendingAcks, globalTunnelID)
		f.pendingMu.Unlock()
	}()

	// Forward connect request to target agent with global tunnel ID
	connectMsg := protocol.NewConnectMessage(globalTunnelID, payload.Protocol, payload.TargetHost, payload.TargetPort)
	if err := f.server.sendToAgent(targetAgent, connectMsg); err != nil {
		log.Printf("Failed to send connect to target agent: %v", err)
		return
	}

	log.Printf("P2P connect: source=%s local=%d -> global=%d -> target=%s, waiting for target ack...",
		sourceAgent.ID, localTunnelID, globalTunnelID, targetAgent.ID)

	// Wait for acknowledgment from target agent
	select {
	case ack := <-ackChan:
		log.Printf("P2P connect: received ack from target, success=%v, error=%s", ack.Success, ack.Error)
		// Send ack to source agent:
		// - msg.TunnelID = localTunnelID (so source can find its pending channel)
		// - payload.TunnelID = globalTunnelID (the actual tunnel ID to use)
		responsePayload := protocol.EncodeConnectAckPayload(&protocol.ConnectAckPayload{
			Success:  ack.Success,
			TunnelID: globalTunnelID, // Tell source agent to use this ID
			Error:    ack.Error,
		})
		ackMsg := protocol.NewMessage(protocol.MsgTypeP2PConnectAck, localTunnelID, responsePayload)
		f.server.sendToAgent(sourceAgent, ackMsg)

		if ack.Success {
			// Register the P2P tunnel mapping with global ID
			f.tunnelConnMu.Lock()
			f.tunnelConns[globalTunnelID] = &TunnelConn{
				ID:            globalTunnelID,
				AgentID:       targetAgent.ID,
				Protocol:      payload.Protocol,
				Target:        fmt.Sprintf("%s:%d", payload.TargetHost, payload.TargetPort),
				SourceAgentID: sourceAgent.ID,
				LocalTunnelID: localTunnelID,
			}
			log.Printf("P2P tunnel %d registered: source=%s, target=%s", globalTunnelID, sourceAgent.ID, targetAgent.ID)
			f.tunnelConnMu.Unlock()

			// Store source agent mapping for reverse data flow
			sourceAgent.tunnelsMu.Lock()
			sourceAgent.tunnels[globalTunnelID] = &Tunnel{
				ID:         globalTunnelID,
				Protocol:   payload.Protocol,
				TargetHost: payload.TargetHost,
				TargetPort: payload.TargetPort,
			}
			sourceAgent.tunnelsMu.Unlock()

			targetAgent.tunnelsMu.Lock()
			targetAgent.tunnels[globalTunnelID] = &Tunnel{
				ID:         globalTunnelID,
				Protocol:   payload.Protocol,
				TargetHost: payload.TargetHost,
				TargetPort: payload.TargetPort,
			}
			targetAgent.ActiveTunnels++
			targetAgent.tunnelsMu.Unlock()

			log.Printf("P2P tunnel established: global=%d source=%s target=%s",
				globalTunnelID, sourceAgent.ID, targetAgent.ID)
		}

	case <-time.After(30 * time.Second):
		ackPayload := protocol.EncodeConnectAckPayload(&protocol.ConnectAckPayload{
			Success:  false,
			TunnelID: localTunnelID,
			Error:    "Connection timeout",
		})
		ackMsg := protocol.NewMessage(protocol.MsgTypeP2PConnectAck, localTunnelID, ackPayload)
		f.server.sendToAgent(sourceAgent, ackMsg)
	}
}

// HandleP2PData handles P2P data from source agent to target agent
func (f *Forwarder) HandleP2PData(sourceAgent *AgentConn, msg *protocol.Message) {
	log.Printf("HandleP2PData called: tunnelID=%d, from agent=%s, size=%d", msg.TunnelID, sourceAgent.ID, len(msg.Payload))

	f.tunnelConnMu.RLock()
	tunnelConn, exists := f.tunnelConns[msg.TunnelID]
	// Debug: list all tunnel IDs
	tunnelIDs := make([]uint32, 0, len(f.tunnelConns))
	for id := range f.tunnelConns {
		tunnelIDs = append(tunnelIDs, id)
	}
	f.tunnelConnMu.RUnlock()

	if !exists {
		log.Printf("P2P data: tunnel %d not found, existing tunnels: %v", msg.TunnelID, tunnelIDs)
		return
	}

	// Forward data to target agent
	targetAgent := f.server.GetAgent(tunnelConn.AgentID)
	if targetAgent == nil {
		log.Printf("P2P data: target agent %s not found", tunnelConn.AgentID)
		return
	}

	log.Printf("P2P data: forwarding %d bytes from source to target agent %s", len(msg.Payload), targetAgent.ID)
	dataMsg := protocol.NewDataMessage(msg.TunnelID, msg.Payload)
	f.server.sendToAgent(targetAgent, dataMsg)
}

// HandleP2PDataReverse handles data from target agent back to source agent
func (f *Forwarder) HandleP2PDataReverse(targetAgent *AgentConn, tunnelID uint32, data []byte) {
	// Get tunnel info to find source agent
	f.tunnelConnMu.RLock()
	tunnelConn, exists := f.tunnelConns[tunnelID]
	f.tunnelConnMu.RUnlock()

	if !exists || tunnelConn.SourceAgentID == "" {
		log.Printf("P2P reverse: tunnel %d not found or no source agent", tunnelID)
		return
	}

	sourceAgent := f.server.GetAgent(tunnelConn.SourceAgentID)
	if sourceAgent == nil {
		log.Printf("P2P reverse: source agent %s not found", tunnelConn.SourceAgentID)
		return
	}

	log.Printf("P2P reverse: forwarding %d bytes from target to source agent %s", len(data), sourceAgent.ID)
	// Send data back to source agent with the global tunnel ID
	// Source agent will map it using its stored global->local mapping
	dataMsg := protocol.NewMessage(protocol.MsgTypeP2PData, tunnelID, data)
	f.server.sendToAgent(sourceAgent, dataMsg)
}

